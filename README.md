==Work-in-progress/draft implementation of the Blocktorrent protocol for Bitcoin==

This project contains the early beginnings of the Blocktorrent protocol using UDP. Currently, functionality is very limited. The current state is as follows:

 - blocktorrent.py has the following:
 	* Code to make and break "connections" with other blocktorrent peers via UDP. No TCP functionality is present yet. 
 	* Code to run the getblocktemplate RPC and form a CBlock with the result, then serialize and transmit the header to a peer.
 	* Some code (which I think is functional) to handle a representation of what parts of a block a peer has downloaded in the TreeState class. 
 	* Some brief tests in test_bt.py, which you should run with the --username=... and --password=... command line arguments set and with bitcoind RPC running on localhost:8332 for getblocktemplate calls. (Don't run this on a machine with a valuable wallet unless you want your coins stolen.)

 - Also included is a copy of tcatm/halfnode in lib/bitcoinnode.py with fixes to be able to connect to recent versions of bitcoind and download transactions and blocks via the bitcoin p2p protocol. It is not integrated with blocktorrent.py in any way as of yet.

Coding on this project was begun on Feb 19, 2016.

The original description of Blocktorrent can be read at http://toom.im/blocktorrent. An incomplete draft of the BIP for blocktorrent follows.

==Draft BIP==

<pre>
  BIP: bip-jonathantoomim-blocktorrent
  Title: Blocktorrent UDP protocol
  Author: Jonathan Toomim <j@toom.im>
  Status: Draft
  Type: Standards Track
  Created: 2016-07-01
</pre>

==Abstract==

A method is presented for improving block propagation speed and reliability. This method splits blocks into chunks using the block's merkle tree, and allows for different chunks to be fetched efficiently in parallel from different peers over UDP. Further optimizations using previously transmitted transaction data or weak blocks are described. 

==Specification==

===Overview and example===

Peers find each other using the standard Bitcoin p2p protocol. They handshake using a TCP connection on a blocktorrent-only port. Control information is sent simultaneously in duplicate on TCP and UDP. Data is sent on UDP.

The merkle tree structure is used to split the transactions in a block into chunks. Chunks can be referenced by their merkle hash or by their depth and index. Peers first download the internal merkle node hashes at one or more intermediate levels, typically ending at a level with a height (distance to the leaves) between 4 and 8. 






Alice is connected to Bob via the standard Bitcoin p2p protocol on TCP:8333. Bob supports the blocktorrent nServices flag. Alice asks Bob for a list of blocktorrent-supporting peers, with their blocktorrent TCP port numbers. Bob supplies Carol:8334 and Dave:8334.

Alice performs a handshake with TCP://Bob:8334, TCP://Carol:8334 and TCP://Dave:8334. Alice does not connect to Carol:8333 or Dave:8333. Bob, Carol, and Dave tell Alice what blocktorrent features they support, and what preferences they have for bandwidth vs. latency tradeoffs. Bob says he's a home user with limited bandwidth. Carol says she's got plenty of spare bandwidth to share with others. Dave claims to be a miner and requests higher priority. 

Alice mines a new 5 MB block containing 10,000 transactions. This block has a Merkle tree that is 14 levels deep. She sends the header to Bob, Carol, and Dave via TCP:8334, and assigns a job ID of 1 to this block. Simultaneously, via UDP, she also sends job ID, the header, and a few kB of data on the new block to Carol and Dave without waiting for a request. 

The data Alice sends to Carol and Dave gives information on the Merkle tree node hashes. She chooses one level of the tree, such as level 6, and sends all of the Merkle node hashes at that level (32 bytes * 40 nodes = 1280 bytes). Most of these nodes account for 256 transactions. (The last node only contains 16 transactions.) 

Upon receipt, Bob, Carol and Dave verify the header's proof-of-work. Bob and Carol then compute all the parent Merkle hashes, and verify that these hashes belong with the block hash and Merkle root. They then submit requests to Alice for a contiguous group of 256 leaf nodes (transaction hashes). Each group descends from one internal node previously received, and so each group can be verified as belonging in the block once the hashes have been received.

Alice 



===Data structures===

A level can be described as all nodes at some depth from the root node. The root has level 0. A level can be encoded as the lowest 6 bits of a uint8. The two MSB are reserved for context-dependent usage.

Hash sequence:

varint         uint8             varint         pair<varint, uint8>[EXC_COUNT]    char[]
COUNT + DEFAULT_HASH_SIZE + EXCEPTION_COUNT +   (NEXT_EXCEPTION, HASH_SIZE)   +   HASHES


A  hash sequence is a group of encoded hashes. Sequences do not themselves  store any positional information about the hashes. Hash  encoding can  take several forms. The obvious encoding is to simply include all 32  bytes of the hash. Another encoding ("shorthash") is to use a shortened form of the hash, e.g. the last 5 bytes of it, after checking the mempool for possible collisions. Hash  sequences begin with a varint COUNT to encode the number of hashes referenced. After that is a  uint8 to encode the number of bytes included per hash, starting from the [fixme: MSB or LSB? Hashes get reversed sometimes in bitcoin, and we want to make sure the mempool sorting works well for us]. Values below 4 or greater than 32 are reserved. Next come the exceptions array. Each exception is a varint stating the distance to the next exception. The cursor initialized to an index of -1. Thus, if the first two entries are exceptions, the NEXT_EXCEPTION values would be 1 and 1.


A run is a straight sequence of Merkle nodes where each node is either all at the same level (a flat run), at ascending levels traveling leftwards, or at ascending levels traveling rightwards. For convenience, those two types of runs shall be called descending and ascending, respectively. 
 
An ascending run that begins at the left of a pair of siblings will also start with a pair of siblings. Descending runs end with a pair of siblings. 

        ^
       / \
      /\  X
     /\ X
    X  X
  Ascending run  
    
        ^
      /   \
     /     \
    / \    /\
   /\ /\  O  O
  X X X X
  Flat run

The algorithm for computing the next node in an ascending run is as follows:

The current node's index and level are i and lvl.

Find the most recent common ancestor (MRCE) of node(i, lvl) and node(i+1, lvl)

A run can be encoded as a starting level, a two-bit direction (00: straight, 10: up, 01: down), and a starting index, followed by the encoded hashes of the nodes.

Run:

        uint8              varint   Sequence
((DIRECTION<<6) | LEVEL) + START  + SEQUENCE



A workout is a set of one or more runs. Workouts do not need to be contiguous.

Workout:

varint    Run[COUNT]
COUNT  +  RUNS

A lap is a set of runs that can be used to recompute a specific ancestor hash. A lap that can be used to recompute the Merkle root is called a root lap. All laps are workouts, but not all workouts are laps. Laps can be one complete level of the Merkle tree, or it can be a mixture of nodes at different levels. For example, the following five "X"s comprise a valid lap:

       ^
     /   \
    /\    X
   /\/\ 
  X XX X
  
In the tree below, the Xs are comprised of two runs, and comprise a lap around the left node in level 1.

        ^
      /   \
     /     \
    / \    /\
   X  /\  O  O
     X  X
Lap:

Workout
WORKOUT

Hashless workout:

A hashless workout is a workout which does not contain any hashes i.e. each occurrence of the SEQUENCE structure contains only the COUNT field. Hashless workouts are used for job status updates. [I was thinking of just using boolean arrays for that. Level + bitmap can be pretty space-efficient.]

===Messages===


====Blocktorrent TCP messages====

BTVERSION

BTVERACK

BTADDR

DISCONNECT

SET_PARAMS

TEST_MTU

ESTIMATE_BANDWIDTH

OPEN_JOB

CLOSE_JOB


====UDP messages====

JOB_STATE job_id hashless_workout

Each blocktorrent node maintains a list of runs which it has received and verified. This list is initially empty and is updated whenever a node receives a verifiable Merkle branch. Every time this list changes, the node adds the change to each per-peer unacknowleged_runs list, and sends the contents of each unacknowledged_runs to the appropriate peer using hashless_workout field of JOB_STATE messages. This will notify peers that the node has a new Merkle branch available.

JOB_STATE_ACK job_id hashless_workout

The JOB_STATE_ACK message tells the other side "I acknowledge that you have new Merkle branches available for download". When a node receives a JOB_STATE message, it replies with a JOB_STATE_ACK message which echoes the hashless workout it was just sent. The sender of the original JOB_STATE message then uses the JOB_STATE_ACK to remove the appropriate runs from the relevant peer's unacknowleged_runs list, preventing those runs from being sent in subsequent JOB_STATE messages.

PING nonce payload -- used for TEST_MTU and ESTIMATE_BANDWIDTH

...


==Motivation==

Block propagation delays present fairness issues for miners. Miners who receive a full block after a delay are at a disadvantage. This issue is exacerbated with large blocks. 

The current MSG_BLOCK protocol makes inefficient use of network bandwidth in several ways. One, it does not allow a receiver of data to start transmitting until the full block has been downloaded and completely verified. Two, it sends redundant information that can be reconstructed from previously received information, such as transaction broadcasts. Three, it uses TCP exclusively, which suffers greatly in constantly-high packet loss situations, e.g. crossing the border of China [suggestion: avoid mentioning country, instead perhaps add a reference to empirical data]. Four, it downloads the full block from the first peer to announce possession of a block, regardless of the connection quality to that peer.

These design flaws in the MSG_BLOCK protocol limit the capacity of Bitcoin today.

==Rationale==

A separate port and p2p protocol were chosen for two reasons. First, the current protocol assumes that all messages will be processed in order, and includes several messages which require locks on cs_main to be held in the most common implementations. 

==Backward compatibility==

==Implementation==

==Result==

==Future Optimizations==

[ Anything that's not planned to be implemented right from the start can be detailed here (preferably in some well-identifiable subsection), and as the implementation is refined it can be removed from here again. ]

==Copyright==

This document is placed in the public domain.

