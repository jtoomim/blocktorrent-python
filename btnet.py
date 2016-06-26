#!/usr/bin/env python
# Public Domain

'''Network related code for blocktorrent-python.'''

from lib.logs import debuglog, log
import socket, select, threading, time, Queue, thread, random, hashlib, struct

MAGIC_SIZE = 5 # bytes for per-peer magic
RETRY_DELAY = 5 # seconds between retry
RETRY_LIMIT = 5 # number of retry attempts
HASH_SIZE = 8 # bytes for ACK hash


def random_string(length):
    '''Generates string with random contents (8 bit). This is for testing
    only. It is eventually supposed to use a CSPRNG.'''
    r = ''
    for i in range(0, length):
        r += chr(random.randrange(256)) # TODO INSECURE INSECURE INSECURE
    return r


def calculate_hash(t):
    '''Generates hash of message. The hash is used in ACK messages to confirm
    reliable reception of a payload.
    '''
    return hashlib.new('sha256', t).digest()[:HASH_SIZE]
    

def calculate_ack_payload(payload, sequence):
    '''Generate payload for ACK packets. This consists of a hash, to detect
    corruption, and the sequence, to guarantee uniqueness.
    '''
    return calculate_hash(payload) + struct.pack('<H', sequence)


class BTEventLoop:
    '''Asynchronous event loop a.k.a. Reactor pattern. All socket I/O events
    are handled in a single thread (the "event loop thread"). The usual
    guidelines for asynchronous programming apply:
    - Do not block the event loop thread. If you are going to do something
      which takes a while, get a worker thread to do it for you, and when the
      worker is finished, use the add_callback() method to pass control back
      into the event loop thread.
    - If the current thread is not the event loop thread, try not to touch
      anything unless you are sure it won't cause concurrency issues. stop()
      and add_callback() are thread-safe.
    '''
    def __init__(self, read_handler, close_handler):
        self.state = "idle"
        self.e_stop = threading.Event()
        self.event_loop_thread = None
        self.callback_queue = Queue.PriorityQueue()
        self.waker = Waker()
        self.socket = None
        self.read_handler = read_handler
        self.close_handler = close_handler

    def run(self, udp_listen):
        '''Begin event loop. The thread context from which this is called
        will be henceforth known as the event loop thread. This method will
        only exit when the event loop is stopped.
        '''
        while not self.e_stop.isSet():
            self.state = "starting"

            debuglog('btnet', "starting BT server on %i" % udp_listen)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind(('localhost', udp_listen))
            self.event_loop_thread = thread.get_ident()
            self.state = "running"

            while self.state != "closed":
                if self.e_stop.isSet():
                    break

                select_timeout = 30
                # Check for callbacks
                current_time = time.time()
                while self.callback_queue.qsize() > 0:
                    item = self.callback_queue.get(False)
                    if item[0] <= current_time:
                        # Callback delay has passed, so remove item from queue
                        # and do the callback.
                        item[1](*item[2], **item[3])
                    else:
                        # Still need to wait for delay to pass. Adjust select
                        # timeout to perform the required delay.
                        select_timeout = min(select_timeout, item[0] - current_time)
                        # Don't remove items from queue until delay has passed.
                        self.callback_queue.put(item)
                        break
                read_list = [self.socket, self.waker.out_end]
                # select is the only multiplexer available on all
                # platforms (Linux/BSD/Windows).
                rd, wr, ex = select.select(read_list, [], [self.socket], select_timeout)
                
                for s in rd:
                    if s == self.waker.out_end:
                        self.waker.handle_read()
                    else:
                        self.read_handler()
                for s in ex:
                    self.close_handler()

            self.close_handler()

            if not self.e_stop.isSet():
                time.sleep(5)
                debuglog('btnet', "reconnect")
    
    def stop(self):
        self.e_stop.set()
        self.waker.wake()

    def add_callback(self, callback, delay=0, *args, **kwargs):
        '''This will schedule a callback within the context of the
        event loop thread. delay is in seconds. Use a delay of 0 to schedule
        the callback immediately. This method has two uses. It can be used
        to schedule callbacks in the future, much like
        Javascript's setTimeout(). This method can also be used to transfer
        control from another thread into the event loop thread.
        '''
        timeout_as_unix = time.time() + delay
        self.callback_queue.put((timeout_as_unix, callback, args, kwargs))
        if (self.state == "running" and
            (thread.get_ident() != self.event_loop_thread)):
            # We're not in the event loop thread, so select() might be
            # waiting. Wake it up just to be sure that the event loop thread
            # sees the new callback.
            self.waker.wake()


class Waker:
    '''One problem with select() is that there is no easy way to interrupt it.
    This means that if there is a worker thread which has completed its work,
    it has to wait for the select() to return or timeout before anything
    can be sent. A Waker is a connected socket pair, with the receiving one
    added to the select() list. You can force the select() to return by
    shoving bytes into one end of the socket pair - this is exactly what
    the wake() method does.
    '''
    def __init__(self):
        # socket.socketpair() is not available on all platforms.
        # Inspired by https://github.com/zopefoundation/Zope/blob/master/src/ZServer/medusa/thread/select_trigger.py
        self.in_end = socket.socket()
        self.in_end.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        attempts = 0
        # Attempt to connect in_end to another socket. Apparently on Windows
        # this sometimes goes wrong for no apparent reason, and a workaround
        # is to just try again.
        # See http://mail.zope.org/pipermail/zope/2005-July/160433.html for
        # more details.
        while True:
            attempts += 1
            bind_socket = socket.socket()
            bind_socket.bind(('127.0.0.1', 0)) # let OS choose port to bind to
            address = bind_socket.getsockname()
            bind_socket.listen(1)
            try:
                self.in_end.connect(address)
                break # success
            except socket.error, e:
                if e[0] != errno.WSAEADDRINUSE:
                    raise
                if attempts >= 10:
                    self.in_end.close()
                    bind_socket.close()
                    raise BindError('Could not create socket pair')
                bind_socket.close()
        self.out_end, address = bind_socket.accept()
        bind_socket.close()
    
    def handle_read(self):
        self.out_end.recv(1024) # just discard it

    def wake(self):
        self.in_end.send('W')


class BTMessage:
    '''Convenient storage class which can encapsulate and de-encapsulate a
    payload with magic bytes and sequence numbers.
    '''
    MSG_DISCONNECT = 'kthxbai'
    MSG_CONNECT = 'ohai' # basically SYN
    MSG_HEADER = 'heads up!'
    MSG_MULTIPLE = 'multipass'
    MSG_ACK = 'ackk'
    MSG_CONNECT_ACK = 'doge' # basically SYN-ACK
    MSG_BLOCKSTATE = 'treestate'
    MSG_REQUEST_TX = 'canihaztx?'
    MSG_TX = 'tx4u'
    MSG_REQUEST_NODES = 'icanhaznodes'
    MSG_RUN = 'butyoucanthide'
    MSG_MISSING_BLOCK = 'meiyou' # We don't have the header for the block that a peer requested parts of.
    MSG_MISSING_NODES = 'drawingablank' # We don't have the nodes that a peer requested.
    MSG_TXCOUNT_PROOF = 'thisistheendmyonlyfriend'

    def __init__(self, payload, magic, sequence=None):
        self.payload = payload
        self.magic = magic
        self.sequence = sequence
    def __str__(self):
        return self.magic.encode('hex') + ':' + str(self.sequence) + ':' + repr(self.payload)
    def serialize(self):
        seq_stuff = chr(0)
        if self.sequence:
            seq_stuff = chr(1) + struct.pack('<H', self.sequence)
        return self.magic + seq_stuff + str(self.payload)
    @staticmethod
    def deserialize(t):
        magic = t[0:MAGIC_SIZE]
        t = t[MAGIC_SIZE:]
        if t[0] == chr(0):
            sequence = None
            payload = t[1:]
        else:
            sequence = struct.unpack('<H', t[1:3])[0]
            payload = t[3:]
        return BTMessage(payload, magic, sequence)


class UnacknowledgedMessage:
    def __init__(self, t, sequence, error_callback, args, kwargs):
        self.message = t
        self.sequence = sequence
        self.error_callback = error_callback
        self.args = args
        self.kwargs = kwargs
        self.retry_count = 0


class LowLevelPeer:
    '''Handles low-level peer communications.'''
    def __init__(self, hostname, port, event_loop):
        '''hostname can be an IP address.'''
        self.hostname = hostname
        self.host = hostname + ":" + str(port)
        self.addr = (socket.gethostbyname(hostname), port) # addr must be (IP address, port)
        self.magic = random_string(MAGIC_SIZE) # outgoing magic
        self.unacknowledged = {}
        self.sequence = 0
        self.connect_nonce = random_string(2 * HASH_SIZE) # outgoing nonce
        self.event_loop = event_loop
        self.unacknowledged = {}
    def __str__(self):
        return str(self.host)
    def send_message(self, t, sequence=None):
        '''Send the contents of t to the peer. If calling this method from
        elsewhere, don't use the sequence argument.
        '''
        m = BTMessage(t, self.magic, sequence)
        debuglog('btnet', "Sent to %s: %s" % (str(self), str(m)))
        self.event_loop.socket.sendto(m.serialize(), self.addr)
    def send_message_acknowledged(self, t, error_callback=None, *args, **kwargs):
        '''Send the contents of t to the peer, making a decent effort to make
        sure that the peer received the message reliably. Here, "reliably"
        means contents arrive at the destination uncorrupted. However, messages
        may be duplicated or re-ordered.
        The optional argument error_callback will be called if the message
        could not be delivered reliably. args and kwargs are arguments to that
        callback.
        '''
        self.sequence = (self.sequence + 1) % 65536
        m = UnacknowledgedMessage(t, self.sequence, error_callback, args, kwargs)
        self.send_message(t, self.sequence)
        key = calculate_ack_payload(t, self.sequence)
        self.unacknowledged[key] = m
        self.event_loop.add_callback(self.retry, RETRY_DELAY, key)
    def retry(self, key):
        if key in self.unacknowledged:
            m = self.unacknowledged[key]
            m.retry_count += 1
            if m.retry_count > RETRY_LIMIT:
                if m.error_callback:
                    m.error_callback(*m.args, **m.kwargs)
                del self.unacknowledged[key]
            else:
                self.send_message(m.message, m.sequence)
                self.event_loop.add_callback(self.retry, RETRY_DELAY, key)

        
class BTPeerManager():
    def __init__(self, event_loop, peer_adder):
        self.syn_received = {} # peers in syn-received state, key = (addr, magic)
        self.syn_sent = {} # peers in syn-sent state, key = addr
        self.event_loop = event_loop
        self.peer_adder = peer_adder

    def accept(self, t, addr, magic, sequence):
        '''This is called whenever a new connection request is received.
        Step 2 of three-way handshake.
        Equivalent to TCP listening -> syn-received transition.
        '''
        # addr should be (IP address, port) since it is from recvfrom()
        if addr in self.syn_sent:
            # This is a simultaneous connect, where two nodes are
            # simultaneously connecting to each other. This is expected to`
            # occur fairly often, as a result of some UDP hole punching
            # procedure. We must re-use the existing peer magic values,
            # otherwise there is a race condition where the two peers end
            # up ignoring each other because of mismatching magic.
            peer = self.syn_sent[addr]
            self.syn_received[(addr, magic)] = peer
            debuglog('btnet', "Peer %s simultaneous connect" % str(peer))
        else:
            if (addr, magic) in self.syn_received:
                peer = self.syn_received[(addr, magic)]
            else:
                peer = LowLevelPeer(addr[0], addr[1], self.event_loop)
                self.syn_received[(addr, magic)] = peer
                debuglog('btnet', "Peer %s in syn-received state" % str(peer))
        # TODO: expire stuff in syn_received
        # There is a DoS potential here: a CONNECT flood, analogous
        # to a TCP SYN flood.
        assert len(t.split(BTMessage.MSG_CONNECT, 1)[1]) == 2 * HASH_SIZE
        payload = peer.connect_nonce[:HASH_SIZE]
        payload += calculate_ack_payload(t, sequence)
        peer.send_message(BTMessage.MSG_CONNECT_ACK + payload)
    
    def accept_finish(self, t, addr, magic):
        '''Step 3 of three-way handshake (final ACK).
        Equivalent to TCP syn-received -> established transition.
        '''
        # addr should be (IP address, port) since it is from recvfrom()
        if (addr, magic) in self.syn_received:
            peer = self.syn_received[(addr, magic)]
            h = t.split(BTMessage.MSG_ACK, 1)[1]
            if h == calculate_hash(peer.connect_nonce[:HASH_SIZE]):
                del self.syn_received[(addr, magic)]
                self.peer_adder.addnode(peer, magic)
            else:
                debuglog('btnet', "Got malformed ACK from %s:%i" % addr)
        else:
            debuglog('btnet', "Got unexpected ACK from %s:%i" % addr)

    def connect(self, addr):
        '''Initiate connection to another peer.
        Step 1 of three-way handshake.
        Equivalent to TCP closed -> syn-sent transition.
        '''
        peer = LowLevelPeer(addr[0], addr[1], self.event_loop)
        peer.send_message_acknowledged(BTMessage.MSG_CONNECT + peer.connect_nonce)
        self.syn_sent[peer.addr] = peer
        debuglog('btnet', "Connecting to %s" % str(peer))
    
    def connect_finish(self, t, addr, magic):
        '''This is called whenever the other side has accepted our connection
        request. Step 2 of three-way handshake.
        Equivalent to TCP syn-sent -> established transition.
        '''
        # addr should be (IP address, port) since it is from recvfrom()
        if addr in self.syn_sent:
            payload = t.split(BTMessage.MSG_CONNECT_ACK, 1)[1]
            key = payload[HASH_SIZE:]
            peer = self.syn_sent[addr]
            if key in peer.unacknowledged:
                del peer.unacknowledged[key]
                del self.syn_sent[addr]
                if (addr, magic) in self.syn_received:
                    del self.syn_received[(addr, magic)]
                self.peer_adder.addnode(peer, magic)
                # TODO: do we need sequence here?
                peer.send_message(BTMessage.MSG_ACK + calculate_hash(payload[0:HASH_SIZE]))
            else:
                debuglog('btnet', "Got malformed CONNECT-ACK from %s:%i" % addr)
        else:
            debuglog('btnet', "Got unexpected CONNECT-ACK from %s:%i" % addr)

    def process_message(self, m, addr):
        if m.payload.startswith(BTMessage.MSG_CONNECT):
            self.accept(m.payload, addr, m.magic, m.sequence)

        if m.payload.startswith(BTMessage.MSG_ACK):
            self.accept_finish(m.payload, addr, m.magic)
        # TODO: resend CONNECT-ACK if in syn-received state and we receive enough
        # data - this accounts for lost ACKs, while not opening a UDP
        # amplification attack vector.
        
        if m.payload.startswith(BTMessage.MSG_CONNECT_ACK):
            self.connect_finish(m.payload, addr, m.magic)

    def send_ack(self, m, low_level_peer):
        peer.send_message(BTMessage.MSG_ACK + calculate_ack_payload(m.payload, m.sequence))
    
    def recv_ack(self, m, low_level_peer):
        key = m.payload.split(BTMessage.MSG_ACK, 1)[1]
        if key in low_level_peer.unacknowledged:
            del low_level_peer.unacknowledged[key]
        else:
            # This can sometimes happen during simultaneous connect
            debuglog('btnet', "Received malformed ACK from %s: %s" % (str(low_level_peer), key.encode('hex')))

