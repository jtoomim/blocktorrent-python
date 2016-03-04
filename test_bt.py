#!/usr/bin/env python

import blocktorrent
import random, traceback, time, math, simplejson, StringIO
node_count = 4

def blockfromfile(fn):
    # not sure if this works yet
    with open(fn) as f:
        template = simplejson.loads(f.read())
    block = blocktorrent.mininode.CBlock()
    block.nVersion = template['version']
    block.hashPrevBlock = int(template['previousblockhash'], 16)
    block.nTime = template['time']
    block.nBits = int(template['bits'], 16)
    block.nNonce = template['nonce']
    vtx = []
    btx = []
    for tx in template['tx']:
        btx.append(binascii.unhexlify(tx['data']))
        ctx = mininode.CTransaction()
        ctx.deserialize(StringIO.StringIO(btx[-1]))
        ctx.calc_sha256()
        vtx.append(ctx)
        assert ctx.sha256 == int(tx['hash'], 16)
    block.vtx = vtx
    block.calc_merkle_root()
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
        if not i==0:
            n.addnode(('localhost', ports[i-1]))
    return nodes, ports

def run_test(nodes):
    if not blocktorrent.rpcusername or not blocktorrent.rpcpassword:
        print "No username or password has been set for the RPC client. Quitting..."
        return
    blk = blocktorrent.blockfromtemplate(blocktorrent.gbt())
    headerinfo = `blk`
    headerinfo = headerinfo.split('vtx=[')[0] + 'vtx[...])'
    print "Getblocktemplate from RPC produced:", headerinfo
    for peer in nodes[0].peers:
        nodes[0].send_header(blk, peer)

    time.sleep(0.2)
    print "Testing send_blockstate"
    for node in nodes:
        for peer in node.peers:
            node.send_blockstate(node.blockstates[blk.sha256].state, blk.sha256, peer)
    print "Attempting btmerkletree_tests(blk). This doesn't quite work yet, due to BTMerkleTree not checking cousins in addnode(...)."
    btmerkletree_tests(blk)
    print "jobs done"

def close_nodes(nodes):
    for node in nodes:
        node.stop()

def btmerkletree_tests(blk):
    start = time.time()
    mt = blocktorrent.bttrees.BTMerkleTree(blk.hashMerkleRoot)
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

def main():
    treestate_tests()

    try:
        nodes, ports = init_nodes(node_count)
        run_test(nodes)
    except:
        traceback.print_exc()

    time.sleep(1)

    try:
        close_nodes(nodes)
    except:
        traceback.print_exc()


if __name__ == '__main__':
    main()