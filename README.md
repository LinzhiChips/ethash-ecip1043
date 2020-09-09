# ethash-ecip1043
Ethash reference implementation, adapted for ECIP-1043
======================================================

This repository contains
* a runnable version of
  [ethash.py](https://eth.wiki/en/concepts/ethash/ethash)
  that produces the same results as real-life Ethash
* an adaptation (ethash_ecip1043.py) that implements the DAG size limiting
  mechanism proposed in
  [ECIP-1043](https://ecips.ethereumclassic.org/ECIPs/ecip-1043)
* a dummy pool server that implements part of the
  [Ethereum JSON-RPC API](https://eth.wiki/json-rpc/API)
  and that can be used for testing miner implementations

The Web server is still work in progress and ECIP-1043 support is only
very lightly tested.


ethash.py
---------

ethash.py is a slightly cleaned up version of the Ethash reference
implementation. It has been tested with data obtained from real-life
ETH/ETC mining.

run-ethash.py is a program that hashes using ethash.py.
It accepts the following three arguments:
* the decimal epoch number
* the hexadecimal header hash, as a very long integer beginning with 0x
* the hexadecimal nonce, also beginning with 0x

It then computes:
* the seedhash for the requested epoch
* the **compressed** mix, obtained by hashing header plus nonce
* the **result**, obtained from the same operation.

The result is the value that is then used for comparison with the
difficulty target.

Example run:
```
./run-ethash.py 359 0x667c94657d5b6922693e2e6ac77b80861b80ff949c795ef4b18551e8c389a2f1 0x710a38013066d8ce
seed c1dbf14bc84f90759c7c94280874014180ae6af9d9768eda2fc1b7c2725c85f4
cmix f4eda3ca5e96f93fc4e13695461a2c032c430259fb9b00461a0b390b97a6a0d3
res  00000000fed70aa5ab78624bf7500e847d200fa1e88e1103fca12724fb5b35bb
```


ethash_ecip1043.py
------------------

Like ethash.py, but has two additional variables:
* `ecip1043_activation_epoch` defines at epoch at which the DAG size
  is frozen, as defined in ECIP-1043
* `ecip1043_fixed_epoch` is the epoch to whose size the DAG size is set

When invoking the run-ecip1043.py program, these variables can be set
with the command-line option
`--ecip1043`=_activation_epoch_`,`_fixed_epoch_

Example run:
```
./run-ecip1043.py --ecip1043=350,64 359 0x667c94657d5b6922693e2e6ac77b80861b80ff949c795ef4b18551e8c389a2f1 0x710a38013066d8ce
seed c1dbf14bc84f90759c7c94280874014180ae6af9d9768eda2fc1b7c2725c85f4
cmix b00e8f2de5907690031516ecf0c909de92e0d92a8661921a169781d273836f19
res  69276d0c9aef70f8bfc985e2c7d7cb5c639b0939c5a18aeecf0d0e46ceea212e
```


pool.py
-------

pool.py is a very simple pool server that speaks (only) the stratum protocol
that uses eth_getWork.

The pool server allows miners to connect and register, generated mining
jobs for them, and verifies their submissions using ethash_ecip1043.py

### Commands

The following commands can be entered on the pool server's console
(standard input):
* `diff` _bits_   
  The pool difficulty in bits. Defaults to 24 bits.
* `ecip1043` [_activation_*,*_fixed_]   
  Sets the activation and fixed epoch for ECIP-1043. The arguments must be
  decimal numbers. If no arguments are given, an impossibly high activation
  epoch is set, disabling ECIP-1043 mode.
* `epoch` _epoch_   
  The decimal number of the epoch the pool will ask miners to mine in
  (the miners are not told the exact block number).
  To make miners that have already obtained a job from the pool switch to
  the new epoch, use the `job` command after `epoch`.
* `help`   
  In case you get lost.
* `job`   
  Sends a new mining job to all the connected miners that have previously
  sent an eth_getWork request.
* `start` _port_   
  Start the pool server on the specified TCP port. The port is a decimal
  number.
* `submit` _hdr_ _nonce_   
  Submit a mining result, consisting of header and nonce. Both are hexadecimal
  numbers beginning with 0x.

The console is left by sending an EOF.

### Command-line options and arguments

The following options are accepted:

* `-d` _bits_ or `--difficulty=`_bits_   
  Set the difficulty, like with the `diff` command.
* `-c` or `--cache`   
  Enables caching of the cache data. Since computation of the cache is rather
  slow in Python, the cache can optionally be stored in a file. This file is
  named _epoch_`.cache` (Note: for ECIP-1043 support, we will also need to add
  the frozen epoch number.)
* `-e` _epoch_ or `--epoch=`_epoch_   
  Set up the indicated epoch before starting to accept commands or connections.
* `--ecip1043=`_activation_`,`_fixed_   
  The ECIP-1043 epochs, like in ethash_ecip1043.py
* `-q` or `--quick`   
  Quick mode: don't load or generate the cache, accept all submissions.
  This is intended for DAG size testing.
* `-v` or `--verbose`   
  Be a bit more chatty.

There is one optional argument:

* _port_   
  The decimal number of the TCP port on which the pool server listens.
  This starts the pool server before accepting commands, i.e., this
  replaces the `start` command.

### Development status

Very lightly tested.


### Example invocation

```
./pool.py -e 360 -v -c 9999
```

This initializes the pool server for epoch 360, writes the *cache* to
the file `360.cache` (cache generation can take several minutes), then
runs the pool server on TCP port 9999 with verbose reporting enabled.
