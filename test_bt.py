#!/usr/bin/env python

import blocktorrent
from lib import util
import random, traceback, time, math, StringIO, binascii, sys
import json as simplejson
node_count = 4

importmode = 'fromfile' if '--fromfile' in sys.argv else blocktorrent.config.MODE

def blockfromfile(fn):
    with open(fn) as f:
        template = simplejson.loads(f.read())
    block = blocktorrent.mininode.CBlock()
    block.nVersion = template['version']
    block.hashPrevBlock = int(template['previousblockhash'], 16)
    block.nTime = template['curtime']
    block.nBits = int(template['bits'], 16)
    block.nNonce = int(template['noncerange'], 16)
    vtx = []
    btx = []
    for tx in template['transactions']:
        btx.append(binascii.unhexlify(tx['data']))
        ctx = blocktorrent.mininode.CTransaction()
        ctx.deserialize(StringIO.StringIO(btx[-1]))
        ctx.calc_sha256()
        vtx.append(ctx)
        assert ctx.sha256 == int(tx['hash'], 16)
    block.vtx = vtx
    block.hashMerkleRoot = block.calc_merkle_root()
    block.calc_sha256()
    return block


def init_nodes(num_nodes):
    ports = random.sample(range(1024, 65535), num_nodes)
    nodes = []
    for i in range(num_nodes):
        n = blocktorrent.BTUDPClient(ports[i])
        nodes.append(n)
        n.start()
        time.sleep(0.05)
        for j in range(i):
            nodes[i].event_loop.add_callback(nodes[i].peer_manager.connect, 0, (('localhost', ports[j])))
    return nodes, ports

def run_test(nodes):
    if (not blocktorrent.rpcusername or not blocktorrent.rpcpassword) and not importmode == 'fromfile':
        print "No username or password has been set for the RPC client. Quitting..."
        return

    if importmode == 'fromfile':
        print "Importing block from file"
        blk = blockfromfile('blocktemplatefrom20160620')
    else:
        print "Importing block from template"
        blk = blocktorrent.blockfromtemplate(blocktorrent.gbt())
    
    #fixme: add transactions from blk to nodes[0]'s txmempool'
    headerinfo = `blk`
    headerinfo = headerinfo.split('vtx=[')[0] + 'vtx[...])'
    print "Getblocktemplate from RPC produced:", headerinfo
    for peer in nodes[0].peers.values():
        nodes[0].send_header(blk, peer)

    time.sleep(0.2)
    print "Testing send_blockstate"
    for node in nodes:
        for peer in node.peers.values():
            node.send_blockstate(node.merkles[blk.sha256].state, blk.sha256, peer)
    time.sleep(0.1)
    print "hashMerkleroot=%s, blockhash=%s" % tuple(map(lambda x: x[::-1].encode('hex_codec'), map(blocktorrent.mininode.ser_uint256, (blk.hashMerkleRoot, blk.sha256))))
    for node in nodes:
        print node.merkles.values()[0].valid[0][::-1].encode('hex_codec')

    print "Attempting btmerkletree_tests(blk)."
    btmerkletree_tests(blk, nodes[0])

    print "nodes[0] state:", nodes[0].merkles.values()[0].state
    print "nodes[1] state:", nodes[1].merkles.values()[0].state
    missing = nodes[1].merkles.values()[0].state.randmissingfrom(nodes[0].merkles.values()[0].state, generations=5)
    print 'randmissingfrom: ', missing
    print 'nodes[1].peers: ', nodes[1].peers
    nodes[1].send_node_request(nodes[1].peers.values()[0], blk.sha256, missing[0], missing[1], 5)
    time.sleep(0.1)
    print "nodes[0] state:", nodes[0].merkles.values()[0].state
    print "nodes[1] state:", nodes[1].merkles.values()[0].state
    print "nodes[1] merkle:", nodes[1].merkles.values()[0].valid
    print "nodes[1] purg:", nodes[1].merkles.values()[0].purgatory



    print "jobs done"

def close_nodes(nodes):
    for node in nodes:
        node.stop()

def build_random_merkle(count):
    '''Builds merkle tree with specified number of leaf nodes. Leaf nodes
    are random hashes. Each node in the tree is
    a list: [hash, left_subtree, right_subtree]. Leaf
    nodes have left_subtree == [] and right_subtree == [].
    Return tuple: [0] contains a list of (level, index, hash) in the tree.
    [1] contains the merkle tree.
    '''
    hashes = []
    merkle = []
    current_level = int(math.ceil(math.log(count, 2)))
    for i in range(count):
        h = ''
        for j in range(32):
            h += chr(random.randrange(256))
        hashes.append((current_level, i, h))
        merkle.append([h, [], []])
    while True:
        if len(merkle) % 2 > 0:
            merkle.append(merkle[-1])
        new_merkle = []
        current_level -= 1
        for i in range(0, len(merkle), 2):
            parent = util.doublesha(merkle[i][0] + merkle[i + 1][0])
            hashes.append((current_level, i / 2, parent))
            new_merkle.append([parent, merkle[i], merkle[i + 1]])
        merkle = new_merkle
        if len(merkle) == 1: break
    return (hashes, merkle[0])

def compare_merkles(a, b):
    if a[0] != b[0]:
        return False
    if a[1] and a[2] and b[1] and b[2]:
        if a[1][0] == a[2][0] and b[1][0] == b[2][0]:
            # right edge; only compare one child
            return compare_merkles(a[1], b[1])
        return compare_merkles(a[1], b[1]) and compare_merkles(a[2], b[2])
    else:
        return (a[1] == b[1]) and (a[2] == b[2])

def btmerkletree_tests_random():
    while True:
        txcount = int(math.pow(10, random.random() * 4.5)) # uniform in log space
        txcount = max(2, txcount) # there are some bugs with the txcount==1 case
        txcount = min(100000, txcount)
        hashes, merkle = build_random_merkle(txcount)
        mt = blocktorrent.bttrees.BTMerkleTree(merkle[0])
        mt.levels = int(math.ceil(math.log(txcount, 2)))
        mt.txcounthints.append(txcount)
        fill_strategy = random.randrange(4)
        if fill_strategy == 0:
            # Leaf nodes only, randomised
            random.shuffle(hashes)
            new_hashes = []
            for h in hashes:
                if h[0] == mt.levels:
                    new_hashes.append(h)
            hashes = new_hashes
        elif fill_strategy == 1:
            # Everything, randomised
            random.shuffle(hashes)
        elif fill_strategy == 2:
            # Everything, top down, in order
            hashes.sort()
        else:
            # Top down, with some levels missing, in random order
            # This approximates the actual fill strategy that we will
            # use.
            levels = {}
            for i in range(mt.levels + 1):
                levels[i] = []
            for h in hashes:
                levels[h[0]].append(h)
            hashes = []
            for i in range(mt.levels + 1):
                if (random.random() < 0.8) and (i < mt.levels):
                    levels[i] = []
                else:
                    random.shuffle(levels[i])
                    hashes.extend(levels[i])
        for h in hashes:
            #print h[0], h[1]
            if not mt.getnode(h[0], h[1]): # avoid "already validated in tree" warnings
                mt.addhash(h[0], h[1], h[2])
        is_okay = compare_merkles(merkle, mt.valid) # reconstructed merkle tree should match input
        is_okay = is_okay and (len(mt.purgatory) == 0) # should have no keys in purgatory
        is_okay = is_okay and (str(mt.state) == "2") # entire tree should be validated
        print("txcount: " + str(txcount) + " strat: " + str(fill_strategy) + " okay: " + str(is_okay))

def btmerkletree_tests(blk, node):
    start = time.time()
    mt = node.merkles[blk.sha256]
    count = len(blk.vtx)
    mt.levels = int(math.ceil(math.log(count, 2)))
#    mt.txcounthints.append(count-1)
#    mt.txcounthints.append(count+1)
#    mt.txcounthints.append(count/2)
#    mt.txcounthints.append(count/2-1)
#    mt.txcounthints.append(count/2+1)
    mt.txcounthints.append(count)
    for i in range(count):
        mt.addhash(mt.levels, i, blk.vtx[i].sha256)
    print 2**mt.levels, count
    middle = time.time()
    hashcount = `mt.valid`.count("['") + `mt.valid`.count('["')
    print "Found something close to %i hashes (hackishly counted) for a block with %i transactions" % (hashcount, len(blk.vtx))
    print "Nodes still in purgatory:", mt.purgatory.keys()
    print "btmerkletree_tests took %3.6f ms" % (1000*(middle - start))
    print "mt found txcount=%i" % mt.txcount
    #print mt.purgatory
    print "mt.state: \n", mt.state


def treestate_tests():
    t = blocktorrent.bttrees.TreeState()
    assert t.state == [0]
    t.setnode(level=2, index=1, value=1) # add path and children to node
    assert t.state == [1, [1, [0], [1, [0], [0]]], [0]]
    print t.pyramid(), '\n' #   node^   ^chil^dren
    t.setnode(level=2, index=1, value=2) # delete children when we set a node to 2 or 3
    assert t.state == [1, [1, [0], [2]], [0]]
    print t.pyramid(), '\n' #   node^
    t.setnode(level=3, index=2, value=3) # change parents and recreate sibling if we set one to 3
    assert t.state == [1, [1, [0], [1, [3], [2]]], [0]]
    print t.pyramid(), '\n' # parent^ no^de  ^sibling
    t.setnode(level=3, index=3, value=3) # siblings with value 2 or 3 fuse and upgrade their parents
    assert t.state == [1, [1, [0], [3]], [0]]
    print t.pyramid(), '\n' # parent^
    print "You should see a warning appear on the right: ",
    t.setnode(level=4, index=6, value=1) # attempts to forget will be ignored
    assert t.state == [1, [1, [0], [3]], [0]]

    # make it more complicated for the sake of stressing the (de)serialization
    t.setnode(2, 0, 2)
    t.setnode(3, 0, 3)
    t.setnode(4, 13, 2)
    t.setnode(5, 18, 3)
    s = t.serialize()
    t2 = blocktorrent.bttrees.TreeState()
    t2.deserialize(StringIO.StringIO(s))
    assert t.state == t2.state

def test_f(blah):
    print('Hello from callback ' + str(blah))
    
def main():
    treestate_tests()
    random.seed(42) # make it deterministic
    if "--random-merkle" in sys.argv:
        btmerkletree_tests_random()
        return

    try:
        nodes, ports = init_nodes(node_count)
        run_test(nodes)
    except:
        traceback.print_exc()

    time.sleep(1)
    #nodes[0].stop()
    #nodes[1].add_callback(test_f, 0.5, 'a')
    #nodes[1].add_callback(test_f, 1.5, 'b')
    #nodes[2].add_callback(test_f, 2.0, 'c')
    #time.sleep(5)

    try:
        close_nodes(nodes)
    except:
        traceback.print_exc()


if __name__ == '__main__':
    main()

