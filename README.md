===============================================
ElectrumFairChainsX - Reimplementation of ElectrumX Server
===============================================

For a future network with bigger blocks.

* Licence: MIT
* Language: Python (>= 3.6)
* Author: Sebastian Gampe

## Documentation

### ElectrumX Server ( forked source )
See https://electrumx.readthedocs.io/

**Notice: The ElectrumX installation is partionally different ! For Installation follow the Installation instructions below**

### Installation ElectrumFairChainsX

#### Install Python3
Recommend version `3.7.4`

`python3 -V` to check your installed version

Download Python source ( gzipped or tar.gz ) https://www.python.org/downloads/release/python-374/ and extract it
~~~
tar -xvf Python-3.7.4.tgz
cd Python-3.7.4
./configure
make
sudo make install
~~~
alternatively `sudo make altinstall`


#### Install required python packages
~~~
sudo pip3 install aiorpcx
sudo pip3 install attrs
sudo pip3 install plyvel
sudo pip3 install pylru
sudo pip3 install aiohttp
~~~

#### Build and Install ElectrumFairChainsX
~~~
python3 setup.py build
sudo python3 setup.py install
~~~

#### Create SSL Certificate ( optional but recommend )
create a SSL Certificate in fairchains data folder to be able to provide SSL support.

###### Install OpenSSL if not exists on your linux device
~~~
sudo apt-get update
sudo apt-get install openssl
~~~

###### Create SSL Key & Certificate
~~~
cd ~/.fairchains
openssl genrsa -out electrumx.key 2048
openssl req -new -key electrumx.key -out electrumx.csr
openssl x509 -req -days 1825 -in electrumx.csr -signkey electrumx.key -out electrumx.crt
~~~

#### Check the `~/.fairchains/fairchains.conf` settings from FairChains client

Example:
~~~
# netname selects the fairchain to use
netname=FairCoinXchain

# electrumX can only be used when FairChain txindex is enabled
txindex=1

# connection parameter for JSON-RPC / API
# ALL of this 4 parameters are mandatory to use electrumfairchainsX

rpcconnect=127.0.0.1
rpcport=8399
rpcuser=fairchains
rpcpassword=FDFfd2!§2sa
~~~


#### Check `~/.fairchains/<myFairChain>.json` blockchain parameters

###### FairChain Developers / Creators
The JSON-File will created by the `fairchains-tool` ( https://github.com/FairChains/fairchains )

###### FairChain Supporters
If you are not the creator of an public FairChain then you  can try to get it from fairchains-collection repository ( https://github.com/TonyFord/fairchains-collection.git ) or ask the creator.

#### Check `~/.fairchains/<myFairChain>.electrumx.json` electrumX network parameters

###### FairChain Developers / Creators
The creator of FairChain must ensure that some PEERS are available and default ports are known.
For this purposes the creator should create a `<myFairChain>.electrumx.json` file.

Example:
~~~
{
  "PEER_DEFAULT_PORTS" :
  {
    "t": "52811",
    "s": "52812"
  },
  "PEERS" :
  [
      "electrum.example.co s",
      "electrumfair.example.org s"
  ],
  "SERVICES" : [
      "rcp://127.0.0.1:8002",
      "ssl://<server.example.org:52812>"
  ],
  "REPORT_SERVICES" :
  [
     "ssl://<electrum.example.co>:52812"
  ]
}
~~~

`SERVICES` should be the address of the server where peers/clients can connect.
It is recommend to use the default ports for the services, see `PEER_DEFAULT_PORTS`
`REPORT_SERVICES` is the address to a peer where the `SERVICES` will reported.


###### FairChain Supporters
If you are not the creator of an public FairChain then you  can try to get it from fairchains-collection repository ( https://github.com/TonyFord/fairchains-collection.git ) or ask the creator.


#### Variables

[description from forked source](./docs/environment.rst)


###### Differences

| Variable | electrumx | electrumfairchainsx |
| ------ | ------ | ------ |
| `fairchains_path` | - | `/home/USERNAME/.fairchains/`<br>commandline `--fairchains-path <yourpath>` |
| `path_to_fairchains_json` | - | `(fairchains_path)/<your_fairchain_name>.json` |
| `DB_DIRECTORY` | Environment | `(fairchains_path)/<your_fairchain_name>.electrumX` |
| `DAEMON_URL` | Environment | `<rpcuser>:<rpcpassword>@<rpcconnect>:<rpcport>` get from `fairchains.conf` |
| `COIN` | Environment | `FairChains` |
| `SERVICES` | Environment | `SERVICES` get from `(fairchains_path)/<your_fairchain_name>.electrumx.json` |
| `REPORT_SERVICES` | Environment | `REPORT_SERVICES` get from `(fairchains_path)/<your_fairchain_name>.electrumx.json` |
| `SSL_KEYFILE` | Environment | `(fairchains_path)/electrumx.key` |
| `SSL_CERTFILE` | Environment | `(fairchains_path)/electrumx.crt` |


#### [optional but recommend] Create an own user for electrumX server

~~~
sudo adduser <username>
sudo usermod -aG sudo <username>
~~~
https://www.digitalocean.com/community/tutorials/how-to-create-a-sudo-user-on-ubuntu-quickstart
