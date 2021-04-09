# Avrio
<b> Master branch: ![Travis CI](https://api.travis-ci.com/avrio-project/avrio-rs.svg?branch=master) Development branch: ![Travis CI](https://api.travis-ci.com/avrio-project/avrio-rs.svg?branch=development) </b>
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/bc49fd1ca3a04c3cbc427074042293d2)](https://www.codacy.com/gh/avrio-project/avrio-rs/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=avrio-project/avrio-rs&amp;utm_campaign=Badge_Grade)

This is the offical implemention of the avrio protocol. It is written in rust. It's protocol is subject to frequent change and as such no documention exists (however it is in the works) It is currently not ready for usage. For more details please join our [discord](https://discord.gg/4aGKGmm)

## Table of Contents
  - [How to compile](#how-to-compile)
    - [Build optimization](#build-optimization)
    - [Linux](#linux)
      - [Prerequisites](#prerequisites)
        - [Ubuntu](#ubuntu)
        - [Generic Linux](#generic-linux)
  - [File structure](#file-structure)
  - [Contributing](#contributing)
  - [Contributors](#contributors)
  
## How to compile

### Build optimization

The following instructions use the ```--release``` flag. This means that cargo will optimize the code while compiling. It takes considerably longer to compile but makes the executables *much* faster. If you want to compile faster or if you are debugging the code, remove the ```release``` tag and the bins will end up in ```target/debug``` rather than ```target/release```. Please note that using these debug bins will result in a considerably lower vote and hence lower reward. On slower machines, using debug may cause you to receive vote below the minimum (meaning you get banned for an epoch). For this reason, we do not recommend that you remove the ```---release``` tag unless needed.
### Linux

#### Prerequisites
Rust makes abundant use of Rust's syntax extensions and other advanced, unstable features. Because of this, you will need to use a nightly version of Rust. If you already have a working installation of the latest Rust nightly, feel free to skip to the next section.

To install a nightly version of Rust, we recommend using rustup. Install rustup by following the instructions on its website. Once rustup is installed, configure Rust nightly as your default toolchain by running the command:
```
rustup default nightly
```
If you prefer you can use per-directory overrides to use the nightly version only for avrio by running the following command in the directory:

```
rustup override set nightly
```

<span>&#9888;</span>  <b>Warning</b>: Avrio requires the latest version of Rust nightly.

If avrio suddenly stops building, ensure you're using the latest version of Rust nightly and avrio by updating your toolchain and dependencies with:
```
rustup update && cargo update
```
You will also need the following packages: [Boost](https://www.boost.org/), [OpenSSL](https://www.openssl.org/) Cargo (or rustc) and git.

##### Ubuntu

```bash
sudo add-apt-repository ppa:ubuntu-toolchain-r/test -y
sudo apt-get update
sudo apt-get install -y build-essential g++-8 gcc-8 git libboost-all-dev libssl1.0-dev cmake libclang-dev clang
git clone -b master --single-branch https://github.com/avrio-project/avrio-rs/
cd avrio-rs
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
git clone -b master --single-branch https://github.com/avrio-project/avrio-rs/
cd avrio-rs
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

## Contributing
Pull requests are welcomed. If you can help with the code, please fork the repo, make your changes to the forked repo and then open a PR into the development branch. Please <b>NEVER</b> open a PR into the master branch. Any PRs into the master branch without prior authorization will be closed.

## Contributors
A huge thank you to everyone who has controbuted to the avrio codebase:
- [Leo Cornelius (Developer, protocol) ](https://github.com/LeoCornelius)
- [TheDevMinerTV (Developer) ](https://github.com/TheDevMinerTV)
- [KruciferX (Spellcheck, protocol)](https://github.com/kruciferx)
