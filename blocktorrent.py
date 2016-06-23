#!/usr/bin/python
# Public Domain

import config
import lib.logs as logs
from lib.logs import debuglog, log
import socket, select, threading, urllib2, sys, binascii, StringIO, traceback
from lib import authproxy, mininode, util, bttrees
import traceback
import btnet
from btnet import BTMessage

logs.debuglevels.extend(['btnet', 'bttree'])

rpchost = config.RPCHOST
rpcusername = config.RPCUSERNAME
rpcpassword = config.RPCPASSWORD
for arg in sys.argv:
    if arg.startswith('--host='): rpchost = arg.split('--host=')[1].strip()
    if arg.startswith('--username='): rpcusername = arg.split('--username=')[1].strip()
    if arg.startswith('--password='): rpcpassword = arg.split('--password=')[1].strip()

def gbt():
    auth_handler = urllib2.HTTPBasicAuthHandler()
    proxy = authproxy.AuthServiceProxy('http://%s:%s@%s:8332' % (rpcusername, rpcpassword, rpchost))
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


class BTPeer:
    def __init__(self, low_level_peer, incoming_magic):
        self.low_level_peer = low_level_peer
        self.incoming_magic = incoming_magic
        self.inflight = {}
        self.blocks = set()
        #self.txinv = set() # we'll probably want to do this in a more efficient fashion than a set
    def __str__(self):
        return self.low_level_peer.__str__()
    def close(self):
        self.unacknowledged = {}
    def has_header(self, sha256):
        assert type(sha256) == long
        if sha256 in self.inflight:
            return 'header'
        elif sha256 in self.blocks:
            return 'block'
    def log_header(self, sha256):
        if not self.has_header(sha256):
            self.inflight[sha256] = bttrees.BTMerkleTree(sha256)
    def send_message(self, t):
        self.low_level_peer.send_message(t)
    def send_message_acknowledged(self, t, error_callback=None, *args, **kwargs):
        self.low_level_peer.send_message_acknowledged(t, error_callback, args, kwargs)
    

class BTUDPClient(threading.Thread):
    def __init__(self, udp_listen=config.BT_PORT_UDP):
        threading.Thread.__init__(self)
        self.udp_listen = udp_listen
        self.blocks = {}
        self.merkles = {}
        self.event_loop = btnet.BTEventLoop(self.handle_read, self.handle_close)
        self.peer_manager = btnet.BTPeerManager(self.event_loop, self)
        self.peers = {} # currently connected peers, key = (IP, port)
        self.magic_map = {} # currently connected peers, key = (magic, (IP, port))

    def run(self):
        if not logs.logfile:
            logs.logfile = open('debug.log', 'a', 1) # line buffered
        self.event_loop.run(self.udp_listen)
        if logs.logfile:
            logs.logusers -= 1
            if logs.logusers == 0:
                try:
                    logs.logfile.close()
                    logs.logfile = None
                except:
                    traceback.print_exc()
    
    def stop(self):
        self.event_loop.stop()

    def handle_close(self):
        for peer in self.peers.values():
            self.remnode(peer)
        if self.event_loop.state != "closed":
            debuglog('btnet', "close")
            self.event_loop.state = "closed"
            try:
                time.sleep(1) # wait for MSG_DISCONNECT to be sent
                self.event_loop.socket.close()
            except:
                pass

    def handle_read(self):
        packet, addr = self.event_loop.socket.recvfrom(65535)
        self.process_message(packet, addr)
    
    def addnode(self, low_level_peer, magic):
        if not low_level_peer.addr in self.peers:
            peer = BTPeer(low_level_peer, magic)
            self.peers[low_level_peer.addr] = peer
            self.magic_map[(magic, low_level_peer.addr)] = peer
            debuglog('btnet', "Adding peer %s" % str(peer))
        else:
            debuglog('btnet', "Peer %s:%i already exists" % low_level_peer.addr)
    
    def remnode(self, peer):
        if peer:
            addr = peer.low_level_peer.addr
            if addr in self.peers:
                debuglog('btnet', "Removing peer %s" % (str(peer)))
                del self.peers[addr]
                del self.magic_map[(peer.incoming_magic, addr)]
                peer.send_message(BTMessage.MSG_DISCONNECT)
                peer.close()
            else:
                debuglog('btnet', "Peer %s:%i doesn't exist" % addr)

    def process_message(self, packet, addr):
        m = btnet.BTMessage.deserialize(packet)
        peer = None
        if (m.magic, addr) in self.magic_map:
            peer = self.magic_map[(m.magic, addr)]

        debuglog('btnet', "Received from %s: %s" % (':'.join(map(str, addr)), str(m)))

        try:
            if not peer:
                # Not connected yet
                self.peer_manager.process_message(m, addr)
            else:
                # connected
                if m.payload.startswith(BTMessage.MSG_DISCONNECT):
                    self.remnode(peer)

                if m.payload.startswith(BTMessage.MSG_HEADER):
                    self.recv_header(m.payload, peer)

                if m.payload.startswith(BTMessage.MSG_MULTIPLE):
                    self.recv_multiple(m.payload, addr)
                
                if m.payload.startswith(BTMessage.MSG_BLOCKSTATE):
                    self.recv_blockstate(m.payload, peer)
                
                if m.payload.startswith(BTMessage.MSG_ACK):
                    self.recv_ack(m, peer)

                if m.payload.startswith(BTMessage.MSG_REQUEST_NODES):
                    self.recv_node_request(m.payload, peer)

                if m.sequence:
                    if (m.magic, addr) in self.magic_map:
                        peer = self.magic_map[(m.magic, addr)]
                        self.peer_manager.send_ack(m, peer.low_level_peer)

        except:
            debuglog('btnet', 'Malformed UDP message or parsing error')
            debuglog('btnet', traceback.format_exc())
            traceback.print_exc()

    def recv_multiple(self, data, addr):
        s = StringIO.StringIO(data.split(BTMessage.MSG_MULTIPLE, 1)[1])
        count = util.deser_varint(s)
        for i in range(count):
            msg_length = util.deser_varint(s)
            self.process_message(s.read(msg_length), addr)

    def add_header(self, cblock):
        if not cblock.sha256 in self.blocks:
            self.blocks[cblock.sha256] = cblock
            self.merkles[cblock.sha256] = bttrees.BTMerkleTree(cblock.hashMerkleRoot)

    def send_header(self, cblock, peer):
        peer.log_header(cblock.sha256)
        self.add_header(cblock)
        header = mininode.CBlockHeader.serialize(cblock)
        msg = BTMessage.MSG_HEADER + header
        peer.send_message(msg)

    def recv_header(self, data, peer):
        blk = mininode.CBlock()
        f = StringIO.StringIO(data.split(BTMessage.MSG_HEADER, 1)[1])
        mininode.CBlockHeader.deserialize(blk, f)
        blk.calc_sha256()
        self.add_header(blk)
        if not peer.has_header(blk.sha256):
            debuglog('btcnet', "Received header from %s: %s" % (peer, repr(blk)))
        else:
            debuglog('btcnet', "Received duplicate header from %s: %s" % (peer, hex(blk.sha256)[2:]))
        peer.log_header(blk.sha256)
        self.broadcast_header(blk)
    
    def recv_ack(self, m, peer):
        self.peer_manager.recv_ack(m, peer.low_level_peer)

    def recv_blockstate(self, data, peer):
        s = StringIO.StringIO(data.split(BTMessage.MSG_BLOCKSTATE, 1)[1])
        hash = util.deser_uint256(s)
        if peer.has_header(hash) == 'header':
            peer.inflight[hash].state.deserialize(s)
            debuglog('btcnet', "New block state for %i: \n" % hash, peer.inflight[hash])

    def send_blockstate(self, state, hash, peer, level=0, index=0):
        assert peer in self.peers.values()
        msg = BTMessage.MSG_BLOCKSTATE + util.ser_uint256(hash) + state.serialize(level, index)
        peer.send_message(msg)

    def broadcast_header(self, cblock):
        sha = cblock.sha256
        for peer in self.peers.values():
            if not peer.has_header(sha):
                self.send_header(cblock, peer)

    def send_node_request(self, peer, hash, level, index, generations):
        assert level < 253 and generations < 253 and index < 2**level and index < 2**30
        msg = BTMessage.MSG_REQUEST_NODES + util.ser_uint256(hash) + chr(level) + util.ser_varint(index) + chr(generations)
        print "sending message %s to peer %s" % (msg.encode('hex'), str(peer))
        peer.send_message(msg)

    def recv_node_request(self, data, peer):
        s = StringIO.StringIO(data.split(BTMessage.MSG_REQUEST_NODES)[1])
        hash = util.deser_uint256(s)
        level = ord(s.read(1))
        index = util.deser_varint(s)
        generations = ord(s.read(1))
        print "peer", peer, "wants h=%s l=%i i=%i g=%i" % (util.ser_uint256(hash)[::-1].encode('hex'), level, index, generations)