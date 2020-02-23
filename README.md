# Avrio
![Travis CI](https://api.travis-ci.com/avrio-project/avrio-core.svg?branch=master)

This is the rust implementaion of avrio. It currently is not ready for usage, if you wish to join the avrio network please use our [cryptonight based implementaion](https://github.com/avrio-project/avrio).

## How To Compile

### Build Optimization

The following instructions use the ```--release``` flag, this means cargo will optimise the code while compiling. It takes considerably longer to compile but makes the executables *much* faster. If you want to compile faster or if you are debbugging the code remove the ```release``` tag, the bins will end up in ```target/debug``` rather than ```target/release```. Please not using these debug bins will result in a considrebly lower vote and hence lower reward - on slow machines using debug may cause you to recieve bellow the minium vote (meaning you get banned for an epoch), for this reason we do not recomend you remove the ```---release``` tag unless needed.
### Linux

#### Prerequisites

You will need the following packages: [Boost](https://www.boost.org/), [OpenSSL](https://www.openssl.org/), rust and git.

You will also need either Cargo or rustc

##### Ubuntu

```bash
sudo add-apt-repository ppa:ubuntu-toolchain-r/test -y
sudo apt-get update
sudo apt-get install -y build-essential g++-8 gcc-8 git libboost-all-dev libssl1.0-dev cmake
git clone -b master --single-branch https://github.com/avrio-project/avrio-core/
cd avrio-core
cargo build --release
```

The binaries will be in the `target/release` folder when you are complete.

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
The binaries will be in the `target/release` folder when you are complete.

```bash
cd target
./avrio-daemon
```

## File Structure
Each aspect of the code is split up into libiarys (eg database, blockchain, p2p), libiarys are further split up into modules (eg transaction is a module part of the core libary, genesis is a module part of the blockchain lib). If you want to use one of these libs in your code then please add the following to your Cargo.toml and clone this repo into your extern folder
for the blockchain libiary
```avrio_<lib_name> = { path: "extern/<lib_name>" }```
eg 
```avrio_p2p = { path: "extern/p2p" }```
The executables can be found in the bin folder, the testnet executables are in bin/testnet

## Pull Requests
Pull requests are welcomed, if you can help with the code please fork the repo, make your changes to the forked repo and then open a PR into the development branch. Please <b>NEVER</b> open a PR into the master branch, any PRs into the master branch without prior authorisation will be closed.
