# Copyright (c) 2016-2017, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

'''Module providing coin abstraction.

Anything coin-specific should go in this file and be subclassed where
necessary for appropriate handling.
'''

from collections import namedtuple
import re
import struct
from decimal import Decimal
from hashlib import sha256
from functools import partial

import subprocess
import json
import os
from electrumx.server.argv import getArgv

import electrumx.lib.util as util
from electrumx.lib.hash import Base58, hash160, double_sha256, hash_to_hex_str
from electrumx.lib.hash import HASHX_LEN, hex_str_to_hash
from electrumx.lib.script import ScriptPubKey, OpCodes
import electrumx.lib.tx as lib_tx
import electrumx.lib.tx_dash as lib_tx_dash
import electrumx.server.block_processor as block_proc
import electrumx.server.daemon as daemon
from electrumx.server.session import (ElectrumX, DashElectrumX,
                                      SmartCashElectrumX, AuxPoWElectrumX)



Block = namedtuple("Block", "raw header transactions")
OP_RETURN = OpCodes.OP_RETURN


class CoinError(Exception):
    '''Exception raised for coin-related errors.'''


class Coin(object):
    '''Base class of coin hierarchy.'''

    REORG_LIMIT = 200
    # Not sure if these are coin-specific
    RPC_URL_REGEX = re.compile('.+@(\\[[0-9a-fA-F:]+\\]|[^:]+)(:[0-9]+)?')
    VALUE_PER_COIN = 100000000
    CHUNK_SIZE = 2016
    BASIC_HEADER_SIZE = 80
    STATIC_BLOCK_HEADERS = True
    SESSIONCLS = ElectrumX
    DEFAULT_MAX_SEND = 1000000
    DESERIALIZER = lib_tx.Deserializer
    DAEMON = daemon.Daemon
    BLOCK_PROCESSOR = block_proc.BlockProcessor
    HEADER_VALUES = ('version', 'prev_block_hash', 'merkle_root', 'timestamp',
                     'bits', 'nonce')
    HEADER_UNPACK = struct.Struct('< I 32s 32s I I I').unpack_from
    MEMPOOL_HISTOGRAM_REFRESH_SECS = 500
    P2PKH_VERBYTE = bytes.fromhex("00")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    XPUB_VERBYTES = bytes('????', 'utf-8')
    XPRV_VERBYTES = bytes('????', 'utf-8')
    WIF_BYTE = bytes.fromhex("80")
    ENCODE_CHECK = Base58.encode_check
    DECODE_CHECK = Base58.decode_check
    GENESIS_HASH = ('000000000019d6689c085ae165831e93'
                    '4ff763ae46a2a6c172b3f1b60a8ce26f')
    # Peer discovery
    PEER_DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    PEERS = []
    CRASH_CLIENT_VER = None
    BLACKLIST_URL = None

    @classmethod
    def lookup_coin_class(cls, name, net):
        '''Return a coin class given name and network.

        Raise an exception if unrecognised.'''
        req_attrs = ['TX_COUNT', 'TX_COUNT_HEIGHT', 'TX_PER_BLOCK']
        for coin in util.subclasses(Coin):
            if (coin.NAME.lower() == name.lower() and
                    coin.NET.lower() == net.lower()):
                coin_req_attrs = req_attrs.copy()
                missing = [attr for attr in coin_req_attrs
                           if not hasattr(coin, attr)]
                if missing:
                    raise CoinError('coin {} missing {} attributes'
                                    .format(name, missing))
                return coin
        raise CoinError('unknown coin {} and network {} combination'
                        .format(name, net))

    @classmethod
    def sanitize_url(cls, url):
        # Remove surrounding ws and trailing /s
        url = url.strip().rstrip('/')
        match = cls.RPC_URL_REGEX.match(url)
        if not match:
            raise CoinError('invalid daemon URL: "{}"'.format(url))
        if match.groups()[1] is None:
            url += ':{:d}'.format(cls.RPC_PORT)
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
        return url + '/'

    @classmethod
    def genesis_block(cls, block):
        '''Check the Genesis block is the right one for this coin.

        Return the block less its unspendable coinbase.
        '''
        print(cls.NAME)
        header = cls.block_header(block, 0)
        header_hex_hash = hash_to_hex_str(cls.header_hash(header))
        if header_hex_hash != cls.GENESIS_HASH:
            raise CoinError('genesis block has hash {} expected {}'
                            .format(header_hex_hash, cls.GENESIS_HASH))

        return header + bytes(1)

    @classmethod
    def hashX_from_script(cls, script):
        '''Returns a hashX from a script, or None if the script is provably
        unspendable so the output can be dropped.
        '''
        if script and script[0] == OP_RETURN:
            return None
        return sha256(script).digest()[:HASHX_LEN]

    @staticmethod
    def lookup_xverbytes(verbytes):
        '''Return a (is_xpub, coin_class) pair given xpub/xprv verbytes.'''
        # Order means BTC testnet will override NMC testnet
        for coin in util.subclasses(Coin):
            if verbytes == coin.XPUB_VERBYTES:
                return True, coin
            if verbytes == coin.XPRV_VERBYTES:
                return False, coin
        raise CoinError('version bytes unrecognised')

    @classmethod
    def address_to_hashX(cls, address):
        '''Return a hashX given a coin address.'''
        return cls.hashX_from_script(cls.pay_to_address_script(address))

    @classmethod
    def P2PKH_address_from_hash160(cls, hash160):
        '''Return a P2PKH address given a public key.'''
        assert len(hash160) == 20
        return cls.ENCODE_CHECK(cls.P2PKH_VERBYTE + hash160)

    @classmethod
    def P2PKH_address_from_pubkey(cls, pubkey):
        '''Return a coin address given a public key.'''
        return cls.P2PKH_address_from_hash160(hash160(pubkey))

    @classmethod
    def P2SH_address_from_hash160(cls, hash160):
        '''Return a coin address given a hash160.'''
        assert len(hash160) == 20
        return cls.ENCODE_CHECK(cls.P2SH_VERBYTES[0] + hash160)

    @classmethod
    def hash160_to_P2PKH_script(cls, hash160):
        return ScriptPubKey.P2PKH_script(hash160)

    @classmethod
    def hash160_to_P2PKH_hashX(cls, hash160):
        return cls.hashX_from_script(cls.hash160_to_P2PKH_script(hash160))

    @classmethod
    def pay_to_address_script(cls, address):
        '''Return a pubkey script that pays to a pubkey hash.

        Pass the address (either P2PKH or P2SH) in base58 form.
        '''
        raw = cls.DECODE_CHECK(address)

        # Require version byte(s) plus hash160.
        verbyte = -1
        verlen = len(raw) - 20
        if verlen > 0:
            verbyte, hash160 = raw[:verlen], raw[verlen:]

        if verbyte == cls.P2PKH_VERBYTE:
            return cls.hash160_to_P2PKH_script(hash160)
        if verbyte in cls.P2SH_VERBYTES:
            return ScriptPubKey.P2SH_script(hash160)

        raise CoinError('invalid address: {}'.format(address))

    @classmethod
    def privkey_WIF(cls, privkey_bytes, compressed):
        '''Return the private key encoded in Wallet Import Format.'''
        payload = bytearray(cls.WIF_BYTE) + privkey_bytes
        if compressed:
            payload.append(0x01)
        return cls.ENCODE_CHECK(payload)

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        return double_sha256(header)

    @classmethod
    def header_prevhash(cls, header):
        '''Given a header return previous hash'''
        return header[4:36]

    @classmethod
    def static_header_offset(cls, height):
        '''Given a header height return its offset in the headers file.

        If header sizes change at some point, this is the only code
        that needs updating.'''
        assert cls.STATIC_BLOCK_HEADERS
        return height * cls.BASIC_HEADER_SIZE

    @classmethod
    def static_header_len(cls, height):
        '''Given a header height return its length.'''
        return (cls.static_header_offset(height + 1)
                - cls.static_header_offset(height))

    @classmethod
    def block_header(cls, block, height):
        '''Returns the block header given a block and its height.'''
        return block[:cls.static_header_len(height)]

    @classmethod
    def block(cls, raw_block, height):
        '''Return a Block namedtuple given a raw block and its height.'''
        header = cls.block_header(raw_block, height)
        txs = cls.DESERIALIZER(raw_block, start=len(header)).read_tx_block()
        return Block(raw_block, header, txs)

    @classmethod
    def decimal_value(cls, value):
        '''Return the number of standard coin units as a Decimal given a
        quantity of smallest units.

        For example 1 BTC is returned for 100 million satoshis.
        '''
        return Decimal(value) / cls.VALUE_PER_COIN

    @classmethod
    def warn_old_client_on_tx_broadcast(cls, _client_ver):
        return False

# all FairChains and FairCoin blockchain can be provided by class FairChains
# It will setup in
#
# core clients data path
#   /home/<myusername>/.fairchains/  ( default path )
#
#   default datapath can be override by commandline argument
#   example:
#       efcx_server --fairchains-path /home/<myusername>/.faircoin2/
#
# fairchains.conf
#   rpcconnect=127.0.0.1
#   rpcport=8332
#   rpcuser=<myrpcusername>
#   rpcpassword=<myrpcpassword>
#   txindex=1
#   netname=<myFairCoinChain>
#
# <myFairCoinChain>.json ( will created by fairchains_tool and contain all blockchain parameters )
# Notice: to access FairCoin blockchain a json dummy file get get from git repository git.TonyFord/fairchains-collection
#
# <myFairCoinChain>.electrumx.json ( contain default PEERS connection parameters )
# Notice: it is the job of the fairchains creators to establish the first peers. Contact the creators or try to find it in the git.TonyFord/fairchains-collection

class FairChains(Coin):

    def getDB_DIRECTORY(fairchains_path):
        p1 = subprocess.Popen(['cat',fairchains_path+'fairchains.conf'], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(['grep','netname='], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
        output = p2.communicate()[0]
        return str(output).split('netname=')[1].split('\\n')[0]

    def getDAEMON_URL(fairchains_path):
        p1 = subprocess.Popen(['cat',fairchains_path+'fairchains.conf'], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(['grep','rpcuser='], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
        output = p2.communicate()[0]
        rpcuser=str(output).split('rpcuser=')[1].split('\\n')[0]

        p1 = subprocess.Popen(['cat',fairchains_path+'fairchains.conf'], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(['grep','rpcpassword='], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
        output = p2.communicate()[0]
        rpcpassword=str(output).split('rpcpassword=')[1].split('\\n')[0]

        p1 = subprocess.Popen(['cat',fairchains_path+'fairchains.conf'], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(['grep','rpcconnect='], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
        output = p2.communicate()[0]
        rpcconnect=str(output).split('rpcconnect=')[1].split('\\n')[0]

        p1 = subprocess.Popen(['cat',fairchains_path+'fairchains.conf'], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(['grep','rpcport='], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
        output = p2.communicate()[0]
        rpcport=str(output).split('rpcport=')[1].split('\\n')[0]

        return rpcuser + ':' + rpcpassword + '@' + rpcconnect + ':' + rpcport

    def getSHORTNAME(path_to_fairchains_json):
        p1 = subprocess.Popen(['cat',path_to_fairchains_json], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(['grep','currencySymbol'], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
        output = p2.communicate()[0]
        return str(output).split('"')[3]

    def getNAME(path_to_fairchains_json):
        p1 = subprocess.Popen(['cat',path_to_fairchains_json], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(['grep','currencyName'], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
        output = p2.communicate()[0]
        return str(output).split('"')[3]

    def getP2PKH_VERBYTE(path_to_fairchains_json):
        p1 = subprocess.Popen(['cat',path_to_fairchains_json], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(['grep','pubKeyAddrVersion'], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
        output = p2.communicate()[0]
        return hex(int( (str(output).split(':')[1].split(',')[0]) ) )[2:]

    def getP2SH_VERBYTES(path_to_fairchains_json):
        p1 = subprocess.Popen(['cat',path_to_fairchains_json], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(['grep','scriptAddrVersion'], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
        output = p2.communicate()[0]
        return hex(int( (str(output).split(':')[1].split(',')[0]) ) )[2:]

    def getWIF_BYTE(path_to_fairchains_json):
        p1 = subprocess.Popen(['cat',path_to_fairchains_json], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(['grep','secretKeyVersion'], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
        output = p2.communicate()[0]
        return hex(int( (str(output).split(':')[1].split(',')[0]) ) )[2:]

    def getGENESIS_HASH(path_to_fairchains_json):
        p1 = subprocess.Popen(['cat',path_to_fairchains_json], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(['grep','"blockHash"'], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
        output = p2.communicate()[0]
        return str(output).split('"')[3]

    def getTX_COUNT_HEIGHT(path_to_fairchains_json):
        p1 = subprocess.Popen(['cat',path_to_fairchains_json], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(['grep','blockSpacing'], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
        output = p2.communicate()[0]
        blocktime=int( str(output).split(':')[1].split(',')[0] )
        return int(24*3600/blocktime)

    def getRPC_PORT(path_to_fairchains_json):
        p1 = subprocess.Popen(['cat',path_to_fairchains_json], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(['grep','defaultPort'], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
        output = p2.communicate()[0]
        return int( str(output).split(':')[1].split(',')[0] )

    def getPEERS(path_to_fairchains_json):
        file=open(path_to_fairchains_json[:-5]+'.electrumx.json','r')
        J=json.loads( file.read() )
        file.close()
        P=[]
        for i,v in J['PEERS'].items():
            P.append(i+' s')
        return P

    def getPEER_DEFAULT_PORTS(path_to_fairchains_json):
        file=open(path_to_fairchains_json[:-5]+'.electrumx.json','r')
        J=json.loads( file.read() )
        file.close()
        return J['PEER_DEFAULT_PORTS']

    def getSERVICES(path_to_fairchains_json):
        file=open(path_to_fairchains_json[:-5]+'.electrumx.json','r')
        J=json.loads( file.read() )
        file.close()
        return ','.join(J['SERVICES'])

    def getREPORT_SERVICES(path_to_fairchains_json):
        file=open(path_to_fairchains_json[:-5]+'.electrumx.json','r')
        J=json.loads( file.read() )
        file.close()
        return ','.join(J['REPORT_SERVICES'])

    # data path getting params
    fairchains_path=getArgv('--fairchains-path').result
    print(fairchains_path+'fairchains.conf')
    path_to_fairchains_json=fairchains_path+getDB_DIRECTORY(fairchains_path)+'.json'
    print(path_to_fairchains_json)

    # env param replacements
    DB_DIRECTORY=fairchains_path+getDB_DIRECTORY(fairchains_path)+'.electrumX'
    DAEMON_URL=getDAEMON_URL(fairchains_path)
    SERVICES=getSERVICES(path_to_fairchains_json)
    REPORT_SERVICES=getREPORT_SERVICES(path_to_fairchains_json)
    SSL_KEYFILE=fairchains_path+'electrumx.key'
    SSL_CERTFILE=fairchains_path+'electrumx.crt'

    # coin params
    NAME=getNAME(path_to_fairchains_json)
    SHORTNAME = getSHORTNAME(path_to_fairchains_json)
    NET = 'mainnet'
    P2PKH_VERBYTE = getP2PKH_VERBYTE(path_to_fairchains_json)
    P2SH_VERBYTES = [getP2SH_VERBYTES(path_to_fairchains_json)]
    WIF_BYTE = getWIF_BYTE(path_to_fairchains_json)
    GENESIS_HASH = getGENESIS_HASH(path_to_fairchains_json)
    # GENESIS_HASH = ('beed44fa5e96150d95d56ebd5d262578'
    #                 '1825a9407a5215dd7eda723373a0a1d7')
    BASIC_HEADER_SIZE = 108
    HEADER_VALUES = ('version', 'prev_block_hash', 'merkle_root',
                 'payload_hash', 'timestamp', 'creatorId')
    HEADER_UNPACK = struct.Struct('< I 32s 32s 32s I I').unpack_from
    TX_COUNT = getTX_COUNT_HEIGHT(path_to_fairchains_json)+30
    TX_COUNT_HEIGHT = getTX_COUNT_HEIGHT(path_to_fairchains_json)
    TX_PER_BLOCK = 1
    RPC_PORT = getRPC_PORT(path_to_fairchains_json)
    PEER_DEFAULT_PORTS = getPEER_DEFAULT_PORTS(path_to_fairchains_json)
    PEERS = getPEERS(path_to_fairchains_json)

    @classmethod
    def block(cls, raw_block, height):
        '''Return a Block namedtuple given a raw block and its height.'''
        if height > 0:
            return super().block(raw_block, height)
        else:
            return Block(raw_block, cls.block_header(raw_block, height), [])

# class FairCoin is obsolete but for informal purposes -> replaced by class FairChains
class FairCoin(Coin):
    NAME = "FairCoin"
    SHORTNAME = "FAIR"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("5f")
    P2SH_VERBYTES = [bytes.fromhex("24")]
    WIF_BYTE = bytes.fromhex("df")
    GENESIS_HASH = ('beed44fa5e96150d95d56ebd5d262578'
                    '1825a9407a5215dd7eda723373a0a1d7')
    BASIC_HEADER_SIZE = 108
    HEADER_VALUES = ('version', 'prev_block_hash', 'merkle_root',
                     'payload_hash', 'timestamp', 'creatorId')
    HEADER_UNPACK = struct.Struct('< I 32s 32s 32s I I').unpack_from
    TX_COUNT = 505
    TX_COUNT_HEIGHT = 470
    TX_PER_BLOCK = 1
    RPC_PORT = 40405
    PEER_DEFAULT_PORTS = {'t': '51811', 's': '51812'}
    PEERS = [
        'electrum.faircoin.world s',
        'electrumfair.punto0.org s',
    ]

    @classmethod
    def block(cls, raw_block, height):
        '''Return a Block namedtuple given a raw block and its height.'''
        if height > 0:
            return super().block(raw_block, height)
        else:
            return Block(raw_block, cls.block_header(raw_block, height), [])
