# Avrio
(Travis CI)[https://api.travis-ci.com/avrio-project/avrio-core.svg?branch=master]
This is the rust implementaion of avrio. It currently is not ready for usage, if you wish to join the avrio network please use our [cryptonight based implementaion](https://github.com/avrio-project/avrio).

## File Structure
Each aspect of the code is split up into libiarys (eg database, blockchain, p2p), libiarys are further split up into modules (eg transaction is a module part of the core libary, genesis is a module part of the blockchain lib). If you want to use one of these libs in your code then please add the following to your Cargo.toml and clone this repo into your extern folder
for the blockchain libiary
```avrio_<lib_name> = { path: "extern/<lib_name>" }```
eg 
```avrio_p2p = { path: "extern/p2p" }```
The executables can be found in the bin folder, the testnet executables are in bin/testnet

## Pull Requests
Pull requests are welcomed, if you can help with the code please fork the repo, make your changes to the forked repo and then open a PR into the development branch. Please <b>NEVER</b> open a PR into the master branch, any PRs into the master branch without prior authorisation will be closed.
