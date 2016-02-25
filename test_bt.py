#!/usr/bin/env python

import blocktorrent
import random, traceback, time
node_count = 4

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

def close_nodes(nodes):
    for node in nodes:
        node.stop()

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
    t2.deserialize(s)
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