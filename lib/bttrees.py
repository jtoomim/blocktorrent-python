import math, binascii
from hashlib import sha256

import config, util
import logs as logs
from logs import debuglog, log
from util import to_hex

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
        with one or three elements: Either [int nodestate], or
        [int nodestate, [list child1], [list child2]]. Whether the node has
        children can be inferred from the value of nodestate.

        nodestate can have one of four values:

        0 (MISSING): The peer does not have any information about the corresponding
        node in the merkle tree or its decendants. This node will be a leaf
        in the TreeState structure, but not necessarily a leaf in the actual
        merkle tree.

        1 (HASH): The peer has the hash for the corresponding merkle node. The peer
        may or may not have any children's hashes. This tree node will have children.

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
        Gets the state of a node of the tree specified by its level and index.
        If the specified node does not exist in this tree but is described
        by one of its ancestors as MISSING, ALLHASH, or ALLTX, then this method
        will return the state specified by that ancestor.

        level == 0 is the merkle root hash.

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
            s = s[1 + ((i>>L)%2)] # take the left or right subtree
            i = i % (1<<L) # we just took that step; clear the bit for sanity's sake

    def fetchsubtree(self, level, index):
        """
        Fetches a subtree. Returns [] if the subtree is not present.
        """
        assert index < 2**level
        assert level >= 0

        # Algorithm: we walk the tree until we either get to the target
        # or reach a node that speaks for all its decendants

        i = index # of working subtree
        L = level # of working subtree
        s = self.state # the subtree
        while 1:
            if L==0:
                return s
            if s[0] in [0, 2, 3]: # if this node speaks for its decendants or is the target
                return []
            L -= 1
            s = s[1 + ((i>>L)%2)] # take the left or right subtree
            i = i % (1<<L) # we just took that step; clear the bit for sanity's sake

    def setnode(self, level, index, value):
        """
        Sets the state of a node of the tree, specified by its level, index, and
        new value. Creates and destroys nodes as needed to ensure that the TreeState
        node population rules are preserved. For example, setting an internal node to
        a value of 2 will remove all its decendants from the tree (even if they have
        a value of 3 -- careful!).
        """
        assert index < 2**level
        assert level >= 0
        assert level <= config.MAX_DEPTH
        assert value in (0,1,2,3)

        if value == 0:
            raise NotImplementedError # clearing inventory is not supported

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
                s.extend([[v],[v]]) # accidental code emoji
            ancestors.append(s)
            L -= 1
            s = s[1 + ((i>>L)%2)] # take the left or right subtree
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
                s.extend([[0],[0]])

            else: # value == 2 or 3
                del s[:]
                s.append(value)
            ancestors.append(s)

        # now let's go through the ancestors and remove redundancies
        while ancestors:
            s = ancestors.pop()
            if s[0] in (0, 2, 3): continue
            left, right = s[1][0], s[2][0]
            if left == right and (left > 1):
                del s[:]
                s.append(left)
        return

    def pyramid(self):
        def extract(sub, levs, i, pos):
            if len(levs) <= i:
                levs.append([9]*2**i)
            levs[i][pos] = sub[0]
            if sub[0] in (0, 2, 3):
                return
            extract(sub[1], levs, i+1, (pos<<1)+0)
            extract(sub[2], levs, i+1, (pos<<1)+1)
        levels = [[9]]
        extract(self.state, levels, 0, 0)
        spaces = int(2**(len(levels)))
        lines = []
        for i in range(len(levels)): # this formatting isn't quite correct, but it's semi-readable
            level = levels[i]
            s1, s2 = int(math.ceil(spaces/(2**(i+2)))), int(math.floor(spaces/(2**(i+2)))-1)
            lines.append(((((" "*s1+"%i"+" "*s2)*len(level))) % tuple(level)).replace('9', '-'))
        return "\n".join(lines)

    def serialize(self, level=0, index=0):
        """
        Serializes (a subtree of) the tree.

        Each node's value is encoded as two bits. If the value is 0b01, then
        the value will be followed with the serialization of its left subtree,
        followed by the right subtree.

        This serialization is not maximally efficient, as it stores interal
        nodes that are made redundant by the its children, but the efficiency
        can never be worse than 50% of the theoretical limit.

        Binary packing follows a little endian format -- that is, the first
        node value is the two MSb of the first byte. If the number of values
        in the tree is not divisible by four, then the LSBs of the last byte
        will be zero-padded.
        """
        flat = self._flatten(self.fetchsubtree(level, index))
        bytes, j, b = [], 0, 0
        for i in range(len(flat)):
            b = b | (flat[i] << (2*(3-j)))
            if j == 3:
                bytes.append(b)
                b = 0
            j = (j+1) % 4
        if j: bytes.append(b) # don't forget the last byte
        return ''.join(map(chr, bytes))

    def _flatten(self, subtree=None):
        """
        Helper method for self.serialize(...). Walks the subtree recursively and
        compiles a list of node values.
        """
        # Another algorithm that might be faster in python is to repr(self.state)
        # and remove all non-numeric characters... but that wouldn't port over to
        # C++ well. So we do it this way.
        res = []
        if subtree == None: subtree = self.state
        if not subtree: return res
        v = subtree[0]
        res.append(v)
        if v == 1:
            res.extend(self._flatten(subtree[1]))
            res.extend(self._flatten(subtree[2]))
        return res

    def deserialize(self, data):
        flat = []
        bytes, j = [], 0
        for i in range(len(data)*4):
            b = data[i//4]
            flat.append((ord(b)>> (2*(3-j)) & 3))
            j = (j+1) % 4
        self.state = self._fatten(flat)[0]

    def _fatten(self, flat):
        v = flat[0]
        subtree = [v]
        if v in (0, 2, 3):
            return subtree, flat[1:]
        l, rem1 = self._fatten(flat[1:])
        r, rem2 = self._fatten(rem1)
        subtree.extend([l, r])
        return subtree, rem2

    def __str__(self):
        return self.pyramid()


class BTMerkleTree:
    """
    Class to build and incrementally validate a merkle tree for a block. This
    class allows for transactions or internal node hashes to be added in
    any order, and will distinguish between known-valid nodes (nodes that have
    been connected to the merkle root hash) stored in the self.valid tree,
    and nodes that are currently just candidates (stored in self.purgatory
    dict).
    """

    def __init__(self, root):
        if type(root) == long:
            root = util.ser_uint256(root)
        self.valid = [root, [], []]
        # A dict for purgatory is a bit of a hack, and should probably be fixed before switching to C++.
        self.purgatory = {} # key = (level, index); value = [candidate hashes]
        self.peerorigins = {} # key = hash, value = peer
        self.txcounthints = [] # we can't trust it when a peer says how many txes there are, so they're just hints

    def getnode(self, level, index, subtree=False):
        """
        Gets the hash at the specified level and index of the validated tree.
        If that node has not yet been added, None will be returned.
        """
        assert index < 2**level
        assert level >= 0
        assert level <= config.MAX_DEPTH
        i = index # of subtree
        L = level # of subtree
        s = self.valid # the subtree
        while 1:
            if L==0: # this node is the target
                if subtree:
                    return s
                elif not s:
                    return None
                else:
                    return s[0]
            elif len(s) < 3:
                return None
            L -= 1
            s = s[1 + ((i>>L)%2)] # take the left or right subtree
            i = i % (1<<L) # we just took that step; clear the bit for sanity's sake

    def setnode(self, level, index, hash):
        """
        Sets the hash at the specified level and index of the validated tree.
        The parent hash must have already been added.
        """
        assert index < 2**level
        assert level >= 0
        assert level <= config.MAX_DEPTH
        i = index # of subtree
        L = level # of subtree
        s = self.valid # the subtree
        while 1:
            if L==0: # this node is the target
                s.extend([hash, [], []])
                return
            elif len(s) < 3:
                debuglog('bttree', 'setnode(%i, %i, hash) found undersized element at %i, %i: %s' % (level, index, L, i, `s`))
                raise
            L -= 1
            s = s[1 + ((i>>L)%2)] # take the left or right subtree
            i = i % (1<<L) # we just took that step; clear the bit for sanity's sake


    def addhash(self, level, index, hash, peer=None):
        """
        Adds a hash to either the validated tree (when possible) or to the
        unvalidated cache, self.purgatory. This will also add any computed parent
        hashes recursively. If the hash makes it into the validated tree, this
        will also check the nephews of this hash to see if they can now be
        validated. However, direct descendents will not be checked, and must be
        checked by the caller.
        """
        if type(hash) == long:
            hash = util.ser_uint256(hash)
        key = (level, index)
        if key in self.purgatory:
            if self.purgatory[key] == hash:
                return
            else:
                oldpeer = self.peerorigins[self.purgatory[key]] if self.purgatory[key] in self.peerorigins else None
                debuglog('btnet', 'Warning: received two different hashes for the same part of a tree. Replacing old hash.')
                debuglog('btnet', 'Cause is likely either network corruption or a malicious peer. Peers:')
                debuglog('btnet', oldpeer, peer)
                debuglog('btnet', 'Hash added is (%i, %i): %s. Oldhash: %s.' % (level, index, to_hex(hash), to_hex(self.purgatory[key])))
                # fixme: peer banning
                # continue to add the new hash and validate
        elif self.getnode(level, index):
            debuglog('bttree', 'Debug warning: level=%i index=%i already validated in tree' % (level, index))
            return
        self.purgatory[key] = hash
        #self.peerorigins[hash] = peer # fixme: make sure memory growth is bounded

        parent = self.getnode(level-1, index//2) # is our parent already valid?
        #if parent: print "valid parent of %i,%i is %i,%i:" %(level, index, level-1, index//2), to_hex(parent])
        siblingkey = (level, index ^ 1)

        if not siblingkey in self.purgatory: # Is this is the right edge of the tree?
            if not index & 1: # if even (left sibling)
                for hint in self.txcounthints:
                    height = int(math.ceil(math.log(hint, 2)))
                    edge = (hint-1) >> (height - level)
                    if index == edge:
                        self.purgatory[siblingkey] = hash # this can be overwritten later
                        break

        if siblingkey in self.purgatory: # then we can check one level up
            sib = self.purgatory[siblingkey]
            parenthash = self.calcparent(sib, hash) if (index%2) else self.calcparent(hash, sib) # left sibling goes first
            if parent and parent == parenthash:
                result = 'connected'
            elif parent and parent != parenthash:
                debuglog('btnet', 'Invalid hash(es) encountered when checking (%i, %i): %s.' % (level, index, to_hex(hash)))
                debuglog('btnet', 'Parent (%i, %i) = %s not %s' %  (level-1, index//2, to_hex(parent), to_hex(parenthash)))
                result = 'invalid'
            else: # recurse one level up
                result = self.addhash(level-1, index//2, parenthash, None)
        else:
            result = 'orphan'

        if result == 'connected':
            self.setnode(level, index, hash)
            self.setnode(level, index^1, sib)
            del self.purgatory[key]
            del self.purgatory[siblingkey]
            # the recursive caller of addhash will take care of the children of key, but not siblingkey
            self.checkchildren(siblingkey[0], siblingkey[1])
        elif result == 'invalid':
            for k in key, siblingkey:
                # fixme: for multi-level recursion, there's a good chance we're deleting the wrong txes.
                # should we delete all of the decendants of the lowest valid hash to which this resolves?
                # or should we leave these hashes all in purgatory? or what? who do we ban?
                debuglog('btnet', 'Invalid hash(es) encountered. Deleting: (%i, %i): %s.' % (k[0], k[1], to_hex(self.purgatory[k])))
                del self.purgatory[k]
        elif result == 'orphan':
            pass # fixme: deal with peer info (and banning) in each of these branches above
        return result

    def checkchildren(self, level, index):
        """
        Recursively checks the descendents of a node to see if they can be
        validated.
        """
        key = (level, index)
        hash = self.getnode(level, index)
        assert hash
        assert not key in self.purgatory
        c1k, c2k = ((level+1, index*2), (level+1, index*2+1)) # child 1/2 key
        keys = [key, c1k, c2k]
        hashes = [hash, None, None]
        for i in range(1, 3):
            k = keys[i]
            hashes[i] = self.purgatory[k] if k in self.purgatory else None
            if not hashes[i]:
                if not keys[i][1] & 1: # if even (left sibling), we check to see if this is the right edge of the tree
                    for hint in self.txcounthints:
                        height = int(math.ceil(math.log(hint, 2)))
                        if keys[i][0] > height: continue
                        edge = (hint-1) >> (height - keys[i][0])
                        if index*2 == edge:
                            hashes[i] = hashes[1] # this can be overwritten later
                            break


                else:
                    if level <= int(math.ceil(math.log(max(self.txcounthints), 2))) and index <= max(self.txcounthints):
                        debuglog('bttree', "Couldn't find hash for %i %i when checking %i %i" % (k[0], k[1], key[0], key[1]))
                    return
        if self.calcparent(hashes[1], hashes[2]) == hashes[0]:
            for i in range(1,3):
                self.setnode(keys[i][0], keys[i][1], hashes[i])
                del self.purgatory[keys[i]]
                self.checkchildren(keys[i][0], keys[i][1])
        else:
            debuglog('bttree', "Invalid descendents encountered in checkchildren. This should not happen. Keys: ", keys)

    def calcparent(self, hash1, hash2):
        if type(hash1) == long:
            hash1 = util.ser_uint256(hash1)
        if type(hash2) == long:
            hash2 = util.ser_uint256(hash2)
        return util.doublesha(hash1 + hash2)


