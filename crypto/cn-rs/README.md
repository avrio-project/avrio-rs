# Cryptonight-rs

[![Build Status](https://travis-ci.org/Team-Hycon/cryptonight-rs.svg?branch=master)](https://travis-ci.org/Team-Hycon/cryptonight-rs)

Cryptonight-rs is a Rust wrapper around Cryptonight hash function from [Monero source code](https://github.com/monero-project/monero).

**This code is not stable yet. It is not recommended to use it in production.**

## Usage

To use Cryptonight-rs, add the following to your Cargo.toml:

```toml
[dependencies]
cryptonight-rs = "^0.2"
```

and the following to your crate root:

```rust
extern crate cryptonight;
use cryptonight::cryptonight;
```

## Test & Benchmark
Clone the repository into local
```rust
cd repo
```
Run test
```rust
cargo test
```

Run benchmark
```rust
cargo bench
```

## Issues & Pull Requests

If you have an issue, feel free to add it to the [Issues](https://github.com/Team-Hycon/cryptonight-rs/issues) tab.
If you'd like to help us out, the [Pull Request](https://github.com/Team-Hycon/cryptonight-rs/pulls) tab is a great place to start.

**If you have found a security bug, please contact us at [security@glosfer.com](security@glosfer.com).**

## Credits

Kudos to [Monero team](https://getmonero.org/community/team/) - C code from https://github.com/monero-project/monero
