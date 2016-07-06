BITCOIN_NODES = [('127.0.0.1', 8333)]

BT_PORT_TCP = 18334
BT_PORT_UDP = 18334

BT_NODES = [('10.0.1.2', 8334)]

RPCHOST = 'localhost'
RPCUSERNAME = ''
RPCPASSWORD = ''

MODE = ''
MAX_DEPTH = 18 # 18 is up to 262,144 transactions, or about 130 MB per block. For testing only.

UPDATE_PEERS_EVERY_N_MS = 100 # send peers an updated state every 100 ms if our local state has even a single change
UPDATE_PEERS_EVERY_N_RUNS = 5 # send peers an updated state immediately if our local state has added this many runs
# Both of the above constants contribute to choosing to send an update even if neither threshold has been met alone;
# e.g. if you have received 60% of the needed runs and have waited 60% of the needed ms, then an update will be sent.

MAX_UPLOAD_BANDWIDTH = 95.0    # Maximum allowed upstream bandwidth that blocktorrent may use, in Mbps.
MAX_DOWNLOAD_BANDWIDTH = 95.0  # Maximum allowed downstream bandwidth that blocktorrent may target, in Mbps.
LEAKY_BUCKET_BUFFER_SISE = 50 # Allow this many kB of data to be queued 
