#!/usr/bin/python2.7

from ethash_ecip1043 import *
import sys

#
# usage: ethash.py [--ecip1043=...] epoch 0xheaderhash 0xnonce
#	   (real-life mode)
#        ethash.py [--ecip1043=...] dag-lines 0xheaderhash 0xnonce
#	   (mixone mode)
#
# --ecip1043=activation_epoch,fixed_epoch
#   activation_epoch is the epoch after which the ECIP-1043 change is
#   in effect. fixed_epoch is the epoch that determines the (then
#   fixed) cache and DAG size when the ECIP-1043 change is active.
#   
#
if len(sys.argv) > 2:
	arg = sys.argv[1].split("=")
	if arg[0] == "--ecip1043":
		activation, fixed = map(lambda x: int(x), arg[1].split(","))
		ecip1043(activation, fixed)
		del sys.argv[1]
if len(sys.argv) != 4:
	print >>sys.stderr, "usage: ", sys.argv[0], \
	    "[--ecip1043=activation_epoch,fixed_epoch", \
	    "epoch|dag-lines", "0xheaderhash", "0xnonce"
	sys.exit(1)

# do exactly what mixone does
if int(sys.argv[1]) > 1000:
	seed = deserialize_hash(get_seedhash(0))
	cache = mkcache(HASH_BYTES, seed)
	dag_bytes = int(sys.argv[1]) * MIX_BYTES
else:
	block = int(sys.argv[1]) * EPOCH_LENGTH
	seed = deserialize_hash(get_seedhash(block))
	print "seed", "%064x" % decode_int(serialize_hash(seed)[::-1])
	cache = mkcache(get_cache_size(block), seed)
	dag_bytes = get_full_size(block)
hdr = encode_int(int(sys.argv[2], base = 16))[::-1]
hdr = '\x00' * (32 - len(hdr)) + hdr
nonce = int(sys.argv[3], base = 16)
hash = hashimoto_light(dag_bytes, cache, hdr, nonce)
print "cmix", "%064x" % decode_int(hash["mix digest"][::-1])
print "res ", "%064x" % decode_int(hash["result"][::-1])
