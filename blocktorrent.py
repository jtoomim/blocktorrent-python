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
from lib import authproxy, halfnode, merkletree

logs.debuglevels.extend(['btnet', 'bttree'])

MSG_DISCONNECT = 'kthxbai'
MSG_CONNECT = 'ohai'
MSG_HEADER = 'heads up!'

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
        self.treeState = TreeState()

class TreeState:
    MISSING = 0
    HASH = 1
    ALLHASH = 2
    ALLTX = 3

    def __init__(self):
        """
        Class to interact with and do basic operations on a data
        structure that stores information about what parts of a merkle
        tree a peer has or does not have. The structure is itself a binary
        tree implemented as nested lists, where a node is a list
        with one or two elements: Either [int nodestate], or
        [int nodestate, [list child1, list child2]]. Whether the node has
        children can be inferred from the value of nodestate.

        nodestate can have one of four values:
        
        0 (MISSING): The peer does not have any information about the corresponding
        node in the merkle tree or its decendants. This node will be a leaf
        in the TreeState structure, but not necessarily a leaf in the actual
        merkle tree.

        1 (HASH): The peer has the hash for the corresponding merkle node. The peer
        may or may not have any children.

        2 (ALLHASH): The peer has the hash for the corresponding merkle node, and
        the hashes for all decendants of this node, up to the transaction
        hashes themselves. The peer is not known to have the actual
        transactions.

        3 (ALLTX): The peer has the hash for this node and all decendants, and has
        the transactions themselves for all decendants.

        If nodestate == 1, then the node entry must include children.
        If nodestate != 1, then the node entry must not include children.
        """
        self.state = [TreeState.MISSING]

    def getnode(self, level, index):
        """
        level 0 is the merkle root hash
        
        index is the position in the corresponding level, and is coincidentally
        also the path that needs to be followed from the root to arrive at the
        desired node, reading the bits from left to right (LSB is the last step
        in the path).
        """
        assert index < 2**level
        assert level >= 0

        # Algorithm: we walk the tree until we either get to the target
        # or reach a node that speaks for all its decendants

        i = index # of subtree
        L = level # of subtree
        s = self.state # the subtree
        while 1:
            if s[0] in [0, 2, 3] or L==0: # if this node speaks for its decendants or is the target
                return s[0] 
            L -= 1
            s = s[1][(i>>L)%2] # take the left or right subtree
            i = i % (1<<L) # we just took that step; clear the bit for sanity's sake
        raise
  
    def setnode(self, level, index, value):
        assert index < 2**level
        assert level >= 0
        assert level <= config.MAX_DEPTH
        assert value in (0,1,2,3)

        if value == 0:
            raise NotImplementedError # deleting nodes is not supported

        # Algorithm: we walk down the tree until we get to the target,
        # creating nodes as needed to get to the target, then we walk back
        # up and clear any nodes that were made redundant by the changes we just made
        # "Down" means away from the root (towards the children)

        i = index # of subtree
        L = level # of subtree
        s = self.state # the subtree

        ancestors = [] # t
        while L > 0:
            v = s[0]
            if v > value: # this can probably happen from out-of-order packets. Remove later.
                debuglog('bttree', 'Debug warning: Parent is more complete than decendants')
                return
            elif v == value and v != 1:
                break
            elif v in (0, 2, 3) and v != value:
                # this node has no children. Let's add them, being careful to mutate
                # the list instead of replacing it in order to ensure that we're modifying
                # the actual tree and not a copied subtree
                assert len(s) == 1
                s[0] = 1
                s.append([[v],[v]]) # accidental code emoji
                
            ancestors.append(s)
            L -= 1
            s = s[1][(i>>L)%2] # take the left or right subtree
            i = i % (1<<L) # we just took that step; clear the bit for sanity's sake

        if L == 0:
            v = s[0]
            if v == value:
                return # nothing to see here, move along
            if v > value: # this can probably happen from out-of-order packets. Remove later.
                return
            if value == 1:
                assert len(s) == 1
                assert s[0] <= value
                s[0] = 1
                s.append([[0],[0]])

            else: # value == 2 or 3
                del s[:]
                s.append(value)
            ancestors.append(s)

        # now let's go through the ancestors and remove redundancies
        while ancestors:
            s = ancestors.pop()
            if s[0] in (0, 2, 3): continue
            left, right = s[1][0][0], s[1][1][0]
            if left == right and (left > 1):
                del s[:]
                s.append(left)
        print self.flattened() # debug, fixme
        return

    def flattened(self):
        def flatten(sub, levs, i, pos):
            if len(levs) <= i:
                levs.append([9]*2**i)
            levs[i][pos] = sub[0]
            if sub[0] in (0, 2, 3):
                return
            flatten(sub[1][0], levs, i+1, (pos<<1)+0)
            flatten(sub[1][1], levs, i+1, (pos<<1)+1)
        levels = [[9]]
        flatten(self.state, levels, 0, 0)
        spaces = 2**(len(levels)-2)
        lines = []
        for level in levels:
            lines.append(((((" "*spaces + "%i")*len(level))) % tuple(level)).replace('9', '-'))
            spaces /= 2
        return "\n".join(lines)

    def __str__(self):
        return self.flattened()


class BTPeer:
    def __init__(self, addr, hostname=None):
        if not hostname: hostname = str(addr[0])
        self.hostname = hostname
        self.host = hostname + ":" + str(addr[1])
        self.headerinv = {}
        self.blockinv = set()
        #self.txinv = set() # we'll probably want to do this in a more efficient fashion than a set


class BTUDPClient(threading.Thread):
    def __init__(self, udp_listen=config.BT_PORT_UDP):
        threading.Thread.__init__(self)
        self.udp_listen = udp_listen
        self.state = "idle"
        self.peers = {}
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
        t, addr = self.socket.recvfrom(8192)
        debuglog('btnet', "Received from %s: %s" % (':'.join(map(str, addr)), repr(t)))

        if t.startswith(MSG_DISCONNECT):
            self.remnode(addr)

        if t.startswith(MSG_CONNECT):
            self.addnode(addr)

        if t.startswith(MSG_HEADER):
            self.recv_header(t, addr)

    def send_header(self, cblock, addr):
        header = cblock.serialize_header()
        msg = MSG_HEADER + header
        self.socket.sendto(msg, addr)

    def recv_header(self, data, addr):
        blk = halfnode.CBlock()
        f = StringIO.StringIO(data.split(MSG_HEADER)[1])
        blk.deserialize_header(f)
        debuglog('btcnet', "Received header from %s: %s" % (self.peers[addr].host, repr(blk)))
        print  "Received header from %s: %s" % (self.peers[addr].host, repr(blk))