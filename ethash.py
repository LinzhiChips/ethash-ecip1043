#!/usr/bin/python2.7

#
# https://github.com/ethereum/wiki/wiki/Ethash
#
# This one points out some issues, but gets several things wrong, too:
# https://github.com/lukovkin/ethash
#
# The issues found in the lokovkin version:
#
# - The encode_int(nonce) does not produce the expected byte string of fixed
#   length 8. Our solution using "struct" should be better.
#
# - Target non-reversal is incorrect, given that we perform a string
#   comparison, which is big-endian.
#

#
# Requires
# python-pysha3
#
# Note: the Keccak hashes are called keccak_*, not sha3_*
# See also: https://pypi.org/project/pysha3/
#

import sha3, copy, struct
from random import randint


# ----- Definitions -----------------------------------------------------------


WORD_BYTES = 4			# bytes in word
DATASET_BYTES_INIT = 2**30	# bytes in dataset at genesis
DATASET_BYTES_GROWTH = 2**23	# dataset growth per epoch
CACHE_BYTES_INIT = 2**24	# bytes in cache at genesis
CACHE_BYTES_GROWTH = 2**17	# cache growth per epoch
EPOCH_LENGTH = 30000		# blocks per epoch
MIX_BYTES = 128			# width of mix
HASH_BYTES = 64			# hash length in bytes
DATASET_PARENTS = 256		# number of parents of each dataset element
CACHE_ROUNDS = 3		# number of rounds in cache production
ACCESSES = 64			# number of accesses in hashimoto loop


# ----- Appendix --------------------------------------------------------------


def decode_int(s):
	return int(s[::-1].encode('hex'), 16) if s else 0


def encode_int(s):
	a = "%x" % s
	return '' if s == 0 else ('0' * (len(a) % 2) + a).decode('hex')[::-1]


def zpad(s, length):
	return s + '\x00' * max(0, length - len(s))


def serialize_hash(h):
	return ''.join([zpad(encode_int(x), 4) for x in h])
  

def deserialize_hash(h):
	return [decode_int(h[i:i+WORD_BYTES])
	    for i in range(0, len(h), WORD_BYTES)]


def hash_words(h, sz, x):
	if isinstance(x, list):
		x = serialize_hash(x)
	y = h(x)
	return deserialize_hash(y)


# sha3 hash function, outputs 64 bytes

def sha3_512(x):
	return hash_words(lambda v: sha3.keccak_512(v).digest(), 64, x)


def sha3_256(x):
	return hash_words(lambda v: sha3.keccak_256(v).digest(), 32, x)


def xor(a, b):
	return a ^ b


def isprime(x):
	for i in range(2, int(x**0.5)):
		if x % i == 0:
			return False
	return True


# ----- Parameters ------------------------------------------------------------


def get_cache_size(block_number):
	sz = CACHE_BYTES_INIT + \
	    CACHE_BYTES_GROWTH * (block_number // EPOCH_LENGTH)
	sz -= HASH_BYTES
	while not isprime(sz / HASH_BYTES):
		sz -= 2 * HASH_BYTES
	return sz


def get_full_size(block_number):
	sz = DATASET_BYTES_INIT + \
	    DATASET_BYTES_GROWTH * (block_number // EPOCH_LENGTH)
	sz -= MIX_BYTES
	while not isprime(sz / MIX_BYTES):
		sz -= 2 * MIX_BYTES
	return sz


# ----- Cache Generation ------------------------------------------------------


def mkcache(cache_size, seed):
	n = cache_size // HASH_BYTES

	# Sequentially produce the initial dataset
	o = [sha3_512(seed)]
	for i in range(1, n):
		o.append(sha3_512(o[-1]))

	# Use a low-round version of randmemohash
	for _ in range(CACHE_ROUNDS):
		for i in range(n):
			v = o[i][0] % n
			o[i] = sha3_512(map(xor, o[(i-1+n) % n], o[v]))

	return o


# ----- Data aggregation function ---------------------------------------------


FNV_PRIME = 0x01000193


def fnv(v1, v2):
	return ((v1 * FNV_PRIME) ^ v2) % 2**32


# ----- Full dataset calculation ----------------------------------------------


def calc_dataset_item(cache, i):
	n = len(cache)
	r = HASH_BYTES // WORD_BYTES
	# initialize the mix
	mix = copy.copy(cache[i % n])
	mix[0] ^= i
	mix = sha3_512(mix)
	# fnv it with a lot of random cache nodes based on i
	for j in range(DATASET_PARENTS):
		cache_index = fnv(i ^ j, mix[j % r])
		mix = map(fnv, mix, cache[cache_index % n])
	return sha3_512(mix)


def calc_dataset(full_size, cache):
	return [calc_dataset_item(cache, i) \
	    for i in range(full_size // HASH_BYTES)]


# ----- Main Loop -------------------------------------------------------------


def hashimoto(header, nonce, full_size, dataset_lookup):
	n = full_size / HASH_BYTES
	w = MIX_BYTES // WORD_BYTES
	mixhashes = MIX_BYTES / HASH_BYTES
	# combine header+nonce into a 64 byte seed
	s = sha3_512(header + struct.pack("<Q", nonce))
	# start the mix with replicated s
	mix = []
	for _ in range(MIX_BYTES / HASH_BYTES):
		mix.extend(s)
	# mix in random dataset nodes
	for i in range(ACCESSES):
		p = fnv(i ^ s[0], mix[i % w]) % (n // mixhashes) * mixhashes
		newdata = []
		for j in range(MIX_BYTES / HASH_BYTES):
			newdata.extend(dataset_lookup(p + j))
		mix = map(fnv, mix, newdata)
	# compress mix
	cmix = []
	for i in range(0, len(mix), 4):
		cmix.append(fnv(fnv(fnv(mix[i], mix[i+1]), mix[i+2]), mix[i+3]))
	return {
		"mix digest": serialize_hash(cmix),
		"result": serialize_hash(sha3_256(s+cmix))
	}


def hashimoto_light(full_size, cache, header, nonce):
	return hashimoto(header, nonce, full_size,
	    lambda x: calc_dataset_item(cache, x))


def hashimoto_full(full_size, dataset, header, nonce):
	return hashimoto(header, nonce, full_size, lambda x: dataset[x])


# ----- Mining ----------------------------------------------------------------

# We break "mine" down into smaller parts, to have better control over the
# mining process.

def get_target(difficulty):
	return zpad(encode_int(2**256 // difficulty), 64)[::-1]


def random_nonce():
	return randint(0, 2**64)


def mine(full_size, dataset, header, difficulty, nonce):
	target = get_target(difficulty)
	while hashimoto_full(full_size, dataset, header, nonce) > target:
		nonce = (nonce + 1) % 2**64
	return nonce


# ----- Defining the Seed Hash ------------------------------------------------


def get_seedhash(block):
	s = '\x00' * 32
	for i in range(block // EPOCH_LENGTH):
		s = serialize_hash(sha3_256(s))
	return s
