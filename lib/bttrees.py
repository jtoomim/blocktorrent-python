import config
import math
import logs as logs
from logs import debuglog, log

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


