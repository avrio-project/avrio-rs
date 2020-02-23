# Avrio
<b> Master branch: ![Travis CI](https://api.travis-ci.com/avrio-project/avrio-core.svg?branch=master) Development branch: ![Travis CI](https://api.travis-ci.com/avrio-project/avrio-core.svg?branch=development) </b>

This is the rust implementation of Avrio. It is currently not ready for usage. If you wish to join the Avrio network, please use our [cryptonight based implementation](https://github.com/avrio-project/avrio).

## How to compile

### Build optimization

The following instructions use the ```--release``` flag. This means that cargo will optimize the code while compiling. It takes considerably longer to compile but makes the executables *much* faster. If you want to compile faster or if you are debugging the code, remove the ```release``` tag and the bins will end up in ```target/debug``` rather than ```target/release```. Please note that using these debug bins will result in a considerably lower vote and hence lower reward. On slower machines, using debug may cause you to receive vote below the minimum (meaning you get banned for an epoch). For this reason, we do not recommend that you remove the ```---release``` tag unless needed.
### Linux

#### Prerequisites

You will need the following packages: [Boost](https://www.boost.org/), [OpenSSL](https://www.openssl.org/), rust and git.

You will also need either Cargo or rustc.

##### Ubuntu

```bash
sudo add-apt-repository ppa:ubuntu-toolchain-r/test -y
sudo apt-get update
sudo apt-get install -y build-essential g++-8 gcc-8 git libboost-all-dev libssl1.0-dev cmake
git clone -b master --single-branch https://github.com/avrio-project/avrio-core/
cd avrio-core
cargo build --release
```

After the completion, the binaries will be in the `target/release` folder.

```bash
cd target
./avrio-daemon
```

##### Generic Linux

Ensure you have the dependencies listed above.


```bash
git clone -b master --single-branch https://github.com/avrio-project/avrio-core/
cd avrio-core
cargo build --release
```
After the completion, the binaries will be in the `target/release` folder.

```bash
cd target
./avrio-daemon
```

## File structure
Each aspect of the code is split up into libraries (e.g. database, blockchain, p2p). Libraries are further split into modules (e.g., transaction is a module part of the core library; genesis is a module part of the blockchain lib). If you want to use one of these libs in your code then please add the following to your Cargo.toml and clone this repo into your extern folder
for the blockchain library
```avrio_<lib_name> = { path: "extern/<lib_name>" }```
e.g. 
```avrio_p2p = { path: "extern/p2p" }```
The executables can be found in the bin folder, the testnet executables are in bin/testnet.

## Pull requests
Pull requests are welcomed. If you can help with the code, please fork the repo, make your changes to the forked repo and then open a PR into the development branch. Please <b>NEVER</b> open a PR into the master branch. Any PRs into the master branch without prior authorization will be closed.
