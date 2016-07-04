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
        self.MTU = 1472 # fixme: do MTU path discovery for this
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
        self.txmempool = {} # store txs

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

                if m.payload.startswith(BTMessage.MSG_TX):
                    self.recv_tx(m.payload, peer) # args?
                
                if m.payload.startswith(BTMessage.MSG_REQUEST_TX):
                    self.send_tx(m.payload, peer) # args?

                # need request_tx func. receive tx req and tx msg
                # asking for specific tx? by txhash, or by blockhash and tx index,
                    # or multiple tx by list of tx indices (offsets). 3 tx in row, 3tx [0,0,0]. would be bandwidth efficient
                # need mempool for txs. dict of tx hashes to tx obj? tx obj from mininode, or other class we write on top
                    # would want to add salted short hashes -- eventually
                # receive req: check mempool. 
                    # how would you check with req by offset or index? 
                    # go into your block db, find that block, find hash that goes at that index, use that to get tx out of mempool
                # Test: fill mempool with data from getblocktemplate, other nodes can req tx from it, they can fill their mempools, get complete blocks
                    # although don't have logic for which parts of merkle tree to req....
                    # write hardcoded thing that sends tx from one to another, check if its received at 2nd peer

                if m.payload.startswith(BTMessage.MSG_REQUEST_NODES):
                    self.recv_node_request(m.payload, peer)

                if m.payload.startswith(BTMessage.MSG_RUN):
                    self.recv_nodes(m.payload, peer)

                if m.payload.startswith(BTMessage.MSG_TXCOUNT_PROOF):
                    self.recv_txcount_proof(m.payload, peer)

                if m.payload.startswith(BTMessage.MSG_MISSING_BLOCK):
                    debuglog('btnet', "MSG_MISSING_BLOCK received, but we can't parse it yet. Payload: %s" % m.payload)

                if m.payload.startswith(BTMessage.MSG_MISSING_NODES):
                    debuglog('btnet', "MSG_MISSING_NODES received, but we can't parse it yet. Payload: %s" % m.payload)

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
            debuglog('btnet', "Received header from %s: %s" % (peer, repr(blk)))
        else:
            debuglog('btnet', "Received duplicate header from %s: %s" % (peer, hex(blk.sha256)[2:]))
        peer.log_header(blk.sha256)
        self.broadcast_header(blk)
    
    def recv_ack(self, m, peer):
        self.peer_manager.recv_ack(m, peer.low_level_peer)

    def recv_blockstate(self, data, peer):
        print 'data in recv_blockstate', data
        s = StringIO.StringIO(data.split(BTMessage.MSG_BLOCKSTATE, 1)[1])
        hash = util.deser_uint256(s)
        if peer.has_header(hash) == 'header':
            peer.inflight[hash].state.deserialize(s)
            debuglog('btnet', "New block state for %i: \n" % hash, peer.inflight[hash])

    # todo: in long run will have blockhash and index or indices, ie level in block ( 5th and 7th tx in block X)
    # two ways node can learn about tx, complete block from file/source or from over network. add to mempool
    def send_tx_req(self, txhash, peer):
        assert peer in self.peers.values()
        msg = BTMessage.MSG_REQUEST_TX + txhash
        # todo: make node stop sending requests after receiving requested tx from peer
        print "Sending tx request for ", txhash
        peer.send_message(msg)
    
    def send_tx(self, data, peer):
        txhash = data.split(BTMessage.MSG_REQUEST_TX, 1)[1]
        for hash in self.txmempool:
            if hash == txhash:
                print "Found requested txhash in mempool, sending tx to peer: ", txhash
                tx = self.txmempool[hash]
                msg = BTMessage.MSG_TX + tx
                peer.send_message(msg)

    # Receive txs from peers, check mempool for hash, add to block if not (identify block?)
    # TXs come through as binary blobs, use mininode CTransaction to deserialize, calc hash
    def recv_tx(self, data, peer):
        ctx = mininode.CTransaction()
        tx = StringIO.StringIO(data.split(BTMessage.MSG_TX, 1)[1])
        mininode.CTransaction.deserialize(ctx, tx)
        ctx.calc_sha256()
        print 'Storing tx received over the network for txhash: ', ctx.hash
        if ctx.hash not in self.txmempool:
            # Store binary blob in mempool... why does output not look the same as test mempool tx blob?
            self.txmempool[ctx.hash] = ctx.serialize() 
            print "Tx serialized and stored in mempool:", self.txmempool[ctx.hash]

    def send_blockstate(self, state, sha256, peer, level=0, index=0):
        assert peer in self.peers.values()
        msg = BTMessage.MSG_BLOCKSTATE + util.ser_uint256(sha256) + state.serialize(level, index)
        peer.send_message(msg)

    def broadcast_header(self, cblock):
        sha = cblock.sha256
        for peer in self.peers.values():
            if not peer.has_header(sha):
                self.send_header(cblock, peer)

    def send_node_request(self, peer, sha256, level, index, generations, complete=0):
        assert level < 253 and generations < 253 and index < 2**level and index < 2**30
        flags = 0
        if complete: flags |= 1
        msg = BTMessage.MSG_REQUEST_NODES + util.ser_uint256(sha256) + chr(level) + util.ser_varint(index) + chr(generations) + util.ser_varint(flags)
        #print "sending message %s to peer %s" % (msg.encode('hex'), str(peer))
        peer.send_message(msg)

    def recv_node_request(self, data, peer):
        s = StringIO.StringIO(data.split(BTMessage.MSG_REQUEST_NODES)[1])
        sha256 = util.deser_uint256(s)
        level = ord(s.read(1))
        index = util.deser_varint(s)
        generations = ord(s.read(1))
        flags = util.deser_varint(s)
        debuglog('btnet', "peer %s wants h=%s l=%i i=%i g=%i f=%i" % (str(peer), util.ser_uint256(sha256)[::-1].encode('hex'), level, index, generations, flags))
        # fixme: maybe add choke/throttle checks here?
        self.send_nodes(peer, sha256, level, index, generations, flags)

    def send_nodes(self, peer, sha256, level, index, generations, flags):
        if not sha256 in self.merkles:
            debuglog('btnet', 'peer %s wants a block that we don\'t know about: %s' % (str(peer), util.ser_uint256(sha256)[::-1].encode('hex')))
            peer.send_message(BTMessage.MSG_MISSING_BLOCK + util.ser_uint256(sha256) + chr(level) + util.ser_varint(index) + chr(generations))
            return
        if not self.merkles[sha256].state.hasdescendants(level, index, generations):
            debuglog('btnet', 'peer %s wants nodes that we don\'t know about: l=%i i=%i g=%i h=%s' % (str(peer), leve, index, generations, util.ser_uint256(sha256)[::-1].encode('hex')))
            peer.send_message(BTMessage.MSG_MISSING_NODES + util.ser_uint256(sha256) + chr(level) + util.ser_varint(index) + chr(generations))
            return
        run = self.merkles[sha256].getrun(level, index, generations)
        assert type(run[0]) == str and len(run[0]) == 32 # Just checking to make sure that merkles stores the serialized str version of the hash, since I forgot

        flags = 0
        if flags: raise NotImplementedError
        msg = BTMessage.MSG_RUN + util.ser_uint256(sha256) + chr(level) + util.ser_varint(index) + chr(generations) + util.ser_varint(len(run)) + util.ser_varint(flags) + ''.join(run)
        if len(msg) > peer.MTU:
            debuglog('btnet', 'MSG_RUN has length %i which exceeds peer %s\'s max MTU of %i' % (len(msg), str(peer), peer.MTU))
        peer.send_message(msg)

    def recv_nodes(self, data, peer):
        s = StringIO.StringIO(data.split(BTMessage.MSG_RUN)[1])
        sha256 = util.deser_uint256(s)
        level = ord(s.read(1))
        index = util.deser_varint(s)
        generations = ord(s.read(1))
        length = util.deser_varint(s)
        flags = util.deser_varint(s)
        if flags: raise NotImplementedError
        run = [s.read(32) for i in range(length)]
        result = self.merkles[sha256].checkaddrun(level, index, generations, length, run)

        if not result:
            print "Failed to add from peer=%s: l=%i i=%i g=%i h=%s" % (str(peer), level, index, generations, util.ser_uint256(sha256)[::-1].encode('hex'))
            debuglog('btnet', "Failed to add from peer=%s: l=%i i=%i g=%i h=%s" % (str(peer), level, index, generations, util.ser_uint256(sha256)[::-1].encode('hex')))

    def send_txcount_proof(self, peer, sha256):
        pass
    def recv_txcount_proof(self, data, peer):
        s = StringIO.StringIO(data.split(BTMessage.MSG_LENGTH_PROOF)[1])
        raise NotImplementedError