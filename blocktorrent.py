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
from lib import authproxy, halfnode, merkletree, util
from lib.util import ser_varint, deser_varint
import lib.bttrees as bttrees
import random

logs.debuglevels.extend(['btnet', 'bttree'])

MAGIC_SIZE = 5
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
    block = halfnode.CBlock()
    block.nVersion = template['version']
    block.hashPrevBlock = int(template['previousblockhash'], 16)
    block.nTime = template['curtime']
    block.nBits = int(template['bits'], 16)
    block.nNonce = int(template['noncerange'], 16)
    vtx = []
    btx = []
    for tx in template['transactions']:
        btx.append(binascii.unhexlify(tx['data']))
        ctx = halfnode.CTransaction()
        ctx.deserialize(StringIO.StringIO(btx[-1]))
        ctx.calc_sha256()
        vtx.append(ctx)
        assert ctx.sha256 == int(tx['hash'], 16)
    block.vtx = vtx
    
    merkle = merkletree.MerkleTree(data=btx, detailed=True)
    block.hashMerkleRoot = int(binascii.hexlify(merkle.merkleRoot()), 16)
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
    def __init__(self, s, addr, hostname=None):
        if not hostname: hostname = str(addr[0])
        self.socket = s
        self.hostname = hostname
        self.host = hostname + ":" + str(addr[1])
        self.addr = addr
        self.headers = {}
        self.blocks = set()
        #self.txinv = set() # we'll probably want to do this in a more efficient fashion than a set
        self.magic = ''
        for i in range(0, MAGIC_SIZE):
            self.magic += chr(random.randrange(256)) # this would be more secure if using a CSPRNG
    def has_header(self, sha256):
        assert type(sha256) == long
        if sha256 in self.headers:
            return 'header'
        elif sha256 in self.blocks:
            return 'block'
    def log_header(self, sha256):
        if not self.has_header(sha256):
            self.headers[sha256] = BlockState(sha256)
    def send_message(self, t):
        self.socket.sendto(self.magic + str(t), self.addr)


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
        self.magic_map = {}

    def addnode(self, addr, magic=None):
        newaddr = (socket.gethostbyname(addr[0]), addr[1])
        if (newaddr in self.peers) and not (magic in self.magic_map):
            # Hack to set correct inbound magic for peer
            # Will remove hack when we have a better handshake sequence
            self.magic_map[magic] = self.peers[newaddr]
        if not newaddr in self.peers:
            peer = BTPeer(self.socket, newaddr, addr[0])
            self.peers[newaddr] = peer
            if magic:
                self.magic_map[magic] = peer
            peer.send_message(MSG_CONNECT)
            debuglog('btnet', "Adding peer %s" % peer.host)
        else:
            debuglog('btnet', "Peer %s:%i already exists" % addr)

    def remnode(self, peer, magic):
        newaddr = (socket.gethostbyname(peer.addr[0]), peer.addr[1])
        if newaddr in self.peers:
            debuglog('btnet', "Removing peer %s" % (self.peers[newaddr].host))
            del self.peers[newaddr]
            del self.magic_map[magic]
            peer.send_message(MSG_DISCONNECT)
        else:
            debuglog('btnet', "Peer %s:%i doesn't exist" % peer.addr)

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
            peer.send_message(MSG_DISCONNECT)
        if self.state != "closed":
            debuglog('btnet', "close")
            self.state = "closed"
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except:
                pass

    def handle_read(self):
        packet, addr = self.socket.recvfrom(65535)
        self.process_message(packet[MAGIC_SIZE:], addr, packet[0:MAGIC_SIZE])

    def process_message(self, t, addr, magic):
        debuglog('btnet', "Received from %s: %s" % (':'.join(map(str, addr)), repr(t)))
        peer = None
        if magic in magic_map:
            peer = magic_map[magic]

        try:
            if t.startswith(MSG_DISCONNECT):
                self.remnode(peer, magic)

            if t.startswith(MSG_CONNECT):
                self.addnode(addr, magic)

            if t.startswith(MSG_HEADER):
                self.recv_header(t, peer)

            if t.startswith(MSG_MULTIPLE):
                self.recv_multiple(t, addr, magic)
        except:
            debuglog('btnet', 'Malformed UDP message or parsing error')
            debuglog('btnet', traceback.format_exc())
            traceback.print_exc()

    def recv_multiple(self, data, addr, magic):
        s = StringIO.StringIO(data.split(MSG_MULTIPLE, 1)[1])
        count = deser_varint(s)
        for i in range(count):
            msg_length = deser_varint(s)
            self.process_message(s.read(msg_length), addr, magic)

    def add_header(self, cblock):
        if not cblock.sha256 in self.blocks:
            self.blocks[cblock.sha256] = cblock
            self.blockstates[cblock.sha256] = BlockState(cblock.sha256)
            #self.merkles[cblock.sha256] = ...

    def send_header(self, cblock, peer):
        peer.log_header(cblock.sha256)
        self.add_header(cblock)
        header = cblock.serialize_header()
        msg = MSG_HEADER + header
        peer.send_message(msg)

    def recv_header(self, data, peer):
        blk = halfnode.CBlock()
        f = StringIO.StringIO(data.split(MSG_HEADER, 1)[1])
        blk.deserialize_header(f)
        blk.calc_sha256()
        self.add_header(blk)
        if not peer.has_header(blk.sha256):
            debuglog('btcnet', "Received header from %s: %s" % (peer.host, repr(blk)))
        else:
            debuglog('btcnet', "Received duplicate header from %s: %i" % (peer.host, hex(blk.sha256)[2:]))
        peer.log_header(blk.sha256)
        self.broadcast_header(blk)

    def broadcast_header(self, cblock):
        sha = cblock.sha256
        for peer in self.peers.values():
            if not peer.has_header(sha):
                self.send_header(cblock, peer)