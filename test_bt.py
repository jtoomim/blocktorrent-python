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

def main():
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