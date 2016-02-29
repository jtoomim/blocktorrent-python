#!/usr/bin/python
# Public Domain

import config
from lib import bitcoinnode
import lib.logs as logs
from lib.logs import debuglog, log
import socket
import select
import threading
import urllib2
import sys
import binascii
import StringIO
from lib import authproxy, mininode, merkletree, util, bttrees

logs.debuglevels.extend(['btnet', 'bttree'])

MSG_DISCONNECT = 'kthxbai'
MSG_CONNECT = 'ohai'
MSG_HEADER = 'heads up!'
MSG_MULTIPLE = 'multipass'

rpcusername = config.RPCUSERNAME
rpcpassword = config.RPCPASSWORD
for arg in sys.argv:
    if arg.startswith('--username='): rpcusername = arg.split('--username=')[1].strip()
    if arg.startswith('--password='): rpcpassword = arg.split('--password=')[1].strip()

def gbt():
    auth_handler = urllib2.HTTPBasicAuthHandler()
    proxy = authproxy.AuthServiceProxy('http://%s:%s@localhost:8332' % (rpcusername, rpcpassword))
    return proxy.getblocktemplate()

def blockfromtemplate(template):
    block = mininode.CBlock()
    block.nVersion = template['version']
    block.hashPrevBlock = int(template['previousblockhash'], 16)
    block.nTime = template['curtime']
    block.nBits = int(template['bits'], 16)
    block.nNonce = int(template['noncerange'], 16)
    vtx = []
    btx = []
    for tx in template['transactions']:
        btx.append(binascii.unhexlify(tx['data']))
        ctx = mininode.CTransaction()
        ctx.deserialize(StringIO.StringIO(btx[-1]))
        ctx.calc_sha256()
        vtx.append(ctx)
        assert ctx.sha256 == int(tx['hash'], 16)
    block.vtx = vtx
    
    block.hashMerkleRoot = block.calc_merkle_root()
    block.calc_sha256()
    return block

class BlockState:
    def __init__(self, sha256):
        self.sha256 = sha256
        self.complete = False
        self.txCount = -1 # unknown
        self.levelCount = -1
        self.bestLevel = 0
        self.treeState = bttrees.TreeState()

class BTPeer:
    def __init__(self, addr, hostname=None):
        if not hostname: hostname = str(addr[0])
        self.hostname = hostname
        self.host = hostname + ":" + str(addr[1])
        self.addr = addr
        self.headers = {}
        self.blocks = set()
        #self.txinv = set() # we'll probably want to do this in a more efficient fashion than a set
    def has_header(self, sha256):
        assert type(sha256) == long
        if sha256 in self.headers:
            return 'header'
        elif sha256 in self.blocks:
            return 'block'
    def log_header(self, sha256):
        if not self.has_header(sha256):
            self.headers[sha256] = BlockState(sha256)


class BTUDPClient(threading.Thread):
    def __init__(self, udp_listen=config.BT_PORT_UDP):
        threading.Thread.__init__(self)
        self.udp_listen = udp_listen
        self.state = "idle"
        self.peers = {}
        self.blocks = {}
        self.blockstates = {}
        self.merkles = {}
        self.e_stop = threading.Event()

    def addnode(self, addr):
        newaddr = (socket.gethostbyname(addr[0]), addr[1])
        if not newaddr in self.peers:
            peer = BTPeer(newaddr, addr[0])
            self.peers[newaddr] = peer
            self.socket.sendto(MSG_CONNECT, newaddr)
            debuglog('btnet', "Adding peer %s" % peer.host)
        else:
            debuglog('btnet', "Peer %s:%i already exists" % addr)

    def remnode(self, addr):
        newaddr = (socket.gethostbyname(addr[0]), addr[1])
        if newaddr in self.peers:
            debuglog('btnet', "Removing peer %s" % (self.peers[newaddr].host))
            del self.peers[newaddr]
            self.socket.sendto(MSG_DISCONNECT, newaddr)
        else:
            debuglog('btnet', "Peer %s:%i doesn't exist" % addr)

    def stop(self):
        self.e_stop.set()

    def run(self):
        if not logs.logfile:
            logs.logfile = open('debug.log', 'a', 1) # line buffered

        while not self.e_stop.isSet():
            self.state = "connecting"

            debuglog('btnet', "starting BT server on %i" % self.udp_listen)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind(('localhost', self.udp_listen))


            epoll = select.epoll()
            epoll.register(self.socket.fileno(), select.EPOLLIN)

            while self.state != "closed":
                if self.e_stop.isSet():
                    break

                events = epoll.poll(timeout=1)
                for fd, ev in events:
                    if ev & select.EPOLLIN:
                        self.handle_read()
                    elif ev & select.EPOLLHUP:
                        self.handle_close()

            self.handle_close()

            if not self.e_stop.isSet():
                time.sleep(5)
                debuglog('btnet', "reconnect")

        if logs.logfile:
            logs.logusers -= 1
            if logs.logusers == 0:
                try:
                    logs.logfile.close()
                    logs.logfile = None
                except:
                    traceback.print_exc()

    def handle_close(self):
        for peer in self.peers:
            # fixme: this needs to be done with TCP to avoid spoofing an IP
            # and interrupting someone else's BT connections
            self.socket.sendto(MSG_DISCONNECT, peer)
        if self.state != "closed":
            debuglog('btnet', "close")
            self.state = "closed"
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except:
                pass

    def handle_read(self):
        t, addr = self.socket.recvfrom(65535)
        self.process_message(t,addr)

    def process_message(self, t, addr):
        debuglog('btnet', "Received from %s: %s" % (':'.join(map(str, addr)), repr(t)))

        try:
            if t.startswith(MSG_DISCONNECT):
                self.remnode(addr)

            if t.startswith(MSG_CONNECT):
                self.addnode(addr)

            if t.startswith(MSG_HEADER):
                self.recv_header(t, addr)

            if t.startswith(MSG_MULTIPLE):
                self.recv_multiple(t, addr)
        except:
            debuglog('btnet', 'Malformed UDP message or parsing error')
            debuglog('btnet', traceback.format_exc())
            traceback.print_exc()

    def recv_multiple(self, data, addr):
        s = StringIO.StringIO(data.split(MSG_MULTIPLE, 1)[1])
        count = util.deser_varint(s)
        for i in range(count):
            msg_length = util.deser_varint(s)
            self.process_message(s.read(msg_length))

    def add_header(self, cblock):
        if not cblock.sha256 in self.blocks:
            self.blocks[cblock.sha256] = cblock
            self.blockstates[cblock.sha256] = BlockState(cblock.sha256)
            #self.merkles[cblock.sha256] = ...

    def send_header(self, cblock, addr):
        self.peers[addr].log_header(cblock.sha256)
        self.add_header(cblock)
        header = mininode.CBlockHeader.serialize(cblock)
        msg = MSG_HEADER + header
        self.socket.sendto(msg, addr)

    def recv_header(self, data, addr):
        blk = mininode.CBlock()
        f = StringIO.StringIO(data.split(MSG_HEADER, 1)[1])
        mininode.CBlockHeader.deserialize(blk, f)
        blk.calc_sha256()
        self.add_header(blk)
        peer = self.peers[addr]
        if not peer.has_header(blk.sha256):
            debuglog('btcnet', "Received header from %s: %s" % (self.peers[addr].host, repr(blk)))
        else:
            debuglog('btcnet', "Received duplicate header from %s: %i" % (self.peers[addr].host, hex(blk.sha256)[2:]))
        peer.log_header(blk.sha256)
        self.broadcast_header(blk)

    def broadcast_header(self, cblock):
        sha = cblock.sha256
        for peer in self.peers.values():
            if not peer.has_header(sha):
                self.send_header(cblock, peer.addr)