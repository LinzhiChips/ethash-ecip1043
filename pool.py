#!/usr/bin/python2.7

from ethash_ecip1043 import *
import math, sys, os
import readline, random, re
import threading, json, argparse, pickle
# renamed in Python 3
import SocketServer as socketserver


# Caches are expensive to compute (at least in Python), so we keep them around
cache_cache = {}

# Current epoch, seed, cache
curr_epoch = None
curr_seed = None
curr_cache = None

# ECIP-1043 settings (we need a local shadow copy since ecip1043_*_epoch are
# value copies, not references)
ecip1043_activation = ecip1043_activation_epoch
ecip1043_fixed = ecip1043_fixed_epoch

# Current difficulty (default to 24 bits)
difficulty = 24

# Caching of cache data
caching = False

# Verbose
verbose = False

# Quick mode - don't generate a cache and don't verify submissions
quick = False

# List of client connections ("handlers")
clients = []


# ----- Ethash operations -----------------------------------------------------


def compute_cache(epoch, block):
	if epoch < ecip1043_activation:
		id = str(epoch)
	else:
		id = str(epoch) + "-" + str(ecip1043_fixed)
	if caching:
		name = id + ".cache"
		try:
			with open(name, "rb") as f:
				print >>sys.stderr, "loading", name
				cache = pickle.load(f)
			return cache
		except:
			print >>sys.stderr, "calculating epoch", \
			    epoch, "cache ..."
			cache = mkcache(get_cache_size(block), curr_seed)
			tmp = id + ".tmp"
			print >>sys.stderr, "saving", tmp
			try:
				with open(tmp, "wb") as f:
					pickle.dump(cache, f)
				os.rename(tmp, name)
				print >>sys.stderr, "saved", name
			except:
				pass
			return cache
	else:
		print >>sys.stderr, "calculating epoch", epoch, "cache ..."
		return mkcache(get_cache_size(block), curr_seed)


def epoch(n):
	global curr_epoch, curr_cache, curr_seed
	global cache_cache

	curr_epoch = n
	block = curr_epoch * EPOCH_LENGTH
	curr_seed = get_seedhash(block)
	if not quick:
		if n < ecip1043_activation:
			key = str(n)
		else:
			key = str(n) + "-" + str(ecip1043_fixed)
		if key not in cache_cache:
			cache_cache[key] = compute_cache(n, block)
		curr_cache = cache_cache[key]


def submit(hdr, nonce, miner_cmix = None):
	if curr_epoch is None:
		print >>sys.stderr, "please set epoch first"
		return False
	if quick:
		if verbose:
			print >>sys.stderr, "ACCEPTED (quick mode)"
		return True
	tmp = encode_int(int(hdr, base = 16))[::-1]
	tmp = '\x00' * (32 - len(tmp)) + tmp
	block = curr_epoch * EPOCH_LENGTH
	cache_bytes = get_cache_size(block)
	dag_bytes = get_full_size(block)
	hash = hashimoto_light(dag_bytes, curr_cache, tmp,
	    int(nonce, base = 16))
	cmix = decode_int(hash["mix digest"][::-1])
	res = decode_int(hash["result"][::-1])
	if verbose:
		print "cmix", "%064x" % cmix
		print "res ", "%064x" % res
	quality = math.log(2 ** 256 / res, 2)
	if verbose:
		print >>sys.stderr, "quality =", quality, "bits"
	if quality < difficulty:
		if verbose:
			print >>sys.stderr, "REJECTED: quality < difficulty"
		return False
	if miner_cmix is not None and cmix != int(miner_cmix, base = 16):
		if verbose:
			print >>sys.stderr, "REJECTED: CMix mismatch"
		return False
	if verbose:
		print >>sys.stderr, "ACCEPTED"
	return True


def job(hdr = None):
	global lock

	if hdr is None:
		hdr = random.getrandbits(256)
	with lock:
		for c in range(len(clients)):
			handler = clients[c]
			if handler.getwork_id is not None:
				res = { "id": handler.getwork_id,
				    "jsonrpc": "2.0",
				    "result": [ "0x%064x" % hdr,
				    "0x%064x" % decode_int(curr_seed[::-1]),
				    "0x%064x" % ((2 ** 256 - 1) /
				    math.pow(2, difficulty)) ]}
				s = json.dumps(res)
				print ">", s
				try:
					# @@@ this is racy
					handler.request.sendall(s + "\n")
				except:
					pass


# ----- Networking ------------------------------------------------------------


# Server object

server = None


def process(j):
	global curr_seed, difficulty, getwork_id

	res = None
	if j["method"] == "eth_submitLogin":
		return { "id": j["id"], "jsonrpc": "2.0", "result": True }, None
	if j["method"] == "eth_getWork":
		if curr_epoch is None:
			print >>sys.stderr, "please set epoch first"
			return None, None
		hdr = random.getrandbits(256)
		return { "id": j["id"], "jsonrpc": "2.0", "result":
		    [ "0x%064x" % hdr,
		      "0x%064x" % decode_int(curr_seed[::-1]),
		      "0x%064x" % ((2 ** 256 - 1) /
		      math.pow(2, difficulty)) ]}, \
		    j["id"]
	if j["method"] == "eth_submitWork":
		p = j["params"]
		if submit(p[1], p[0], p[2]):
			return { "id": j["id"], "jsonrpc": "2.0",
			   "result": True }, None
		else:
			return { "id": j["id"], "jsonrpc": "2.0",
			   "result": False }, None
	if j["method"] == "eth_submitHashrate":
		# accept whatever (and ignore it)
		return { "id": j["id"], "jsonrpc": "2.0", "result": True }, \
		    None
	else:
		print >>sys.stderr, "unrecognized", j
		return { "id": j["id"], "jsonrpc": "2.0", "result": None,
		    "error": { "code": -3, "message": "Method not found" }}, \
		    None


class Handler(socketserver.StreamRequestHandler):
	def handle(self):
		global lock

		with lock:
			clients.append(self)
		self.getwork_id = None
		while True:
			req = self.rfile.readline().strip()
			if not req:
				break
			print "<", req
			res, getwork_id = process(json.loads(req))
			if getwork_id is not None:
				self.getwork_id = getwork_id
			if res is not None:
				s = json.dumps(res)
				print ">", s
				try:
					self.request.sendall(s + "\n")
				except:
					break
		with lock:
			for i in range(len(clients)):
				if clients[i] is self:
					del clients[i]
					break


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
	allow_reuse_address = True


def start(port):
	global server

	if server is not None:
		print >>sys.stderr, "server is already running"
		return
	server = ThreadedTCPServer(("", port), Handler)
	thread = threading.Thread(target=server.serve_forever)
	thread.daemon = True
	thread.start()


# ----- Help and command processing -------------------------------------------


def help():
	print """
diff bits
  set the difficulty, in bits
ecip1043 [activate fixed]
  set the activation epoch for the ECIP-1043 cache and DAG size limitation, and
  the epoch of the fixed size. "ecip1043" without arguments sets the activation
  epoch to an impossibly high value, disabling ECIP-1043 mode.
epoch number
  set the current epoch and calculate the cache (may take a while)
help
  show this help page
job [0xhash]
  issue an unrequested job (optionally, with the given hash)
start port
  start the pool server on the specified port
submit 0xheader 0xnonce
  submit a result"""


parser = argparse.ArgumentParser()
parser.add_argument("-d", "--difficulty", type = int,
    help = "difficulty in bits")
parser.add_argument("-c", "--cache", action = "store_true",
    help = "cache \"cache\" data")
parser.add_argument("-e", "--epoch", type = int, help = "epoch number")
parser.add_argument("--ecip1043", metavar = "ACTIVATION,FIXED",
    help = "ECIP-1043 activation and fixed epoch")
parser.add_argument("-q", "--quick", action = "store_true",
    help = "don't verify submissions")
parser.add_argument("-v", "--verbose", action = "store_true",
    help = "verbose operation")
parser.add_argument("port", type = int, nargs = "?",
    help = "start server on port number")
args = parser.parse_args()

caching = args.cache
quick = args.quick
verbose = args.verbose

if args.difficulty is not None:
	difficulty = args.difficulty
if args.ecip1043 is not None:
	activation, fixed = map(lambda x: int(x), args.ecip1043.split(","))
	ecip1043(activation, fixed)
	ecip1043_activation, ecip1043_fixed = activation, fixed
if args.epoch is not None:
	epoch(args.epoch)

if args.port is not None:
	start(args.port)

lock = threading.Lock()

while True:
	try:
		line = raw_input(("" if curr_epoch is None
		    else str(curr_epoch)) + "> ")
	except (EOFError, KeyboardInterrupt):
		print
		sys.exit(0)
	a = re.compile("\s+").split(line)
	try:
		if a[0] == "":
			continue
		if a[0] == "diff" or a[0] == "difficulty":
			difficulty = int(a[1])
		elif a[0] == "ecip1043":
			if len(a) == 1:
				ecip1043(700000, 0)
				ecip1043_activation, ecip1043_fixed = 700000, 0
			else:
				ecip1043(int(a[1]), int(a[2]))
				ecip1043_activation, ecip1043_fixed = \
				    int(a[1]), int(a[2])
		elif a[0] == "epoch":
			epoch(int(a[1]))
		elif a[0] == "help":
			help()
		elif a[0] == "job":
			if len(a) == 1:
				job()
			else:
				job(int(a[1], base = 16))
		elif a[0] == "start":
			start(int(a[1]))
		elif a[0] == "submit":
			submit(a[1], a[2])
		else:
			raise Exception
	except KeyboardInterrupt:
		break
	except:
		print 'try "help" for help'
