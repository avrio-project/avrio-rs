//! Cryptonight-rs is a Rust wrapper around Cryptonight hash function from [Monero source code](https://github.com/monero-project/monero).
//!
//! # Examples
//!
//! To use Cryptonight-rs, add the following to your Cargo.toml:
//! ```toml
//! [dependencies]
//! cryptonight-rs = "^0.2"
//! ```
//!
//! and the following to your crate root:
//!```rust
//! extern crate cryptonight;
//!
//! use cryptonight::cryptonight;
//! ```
//!
//! # Test & Benchmark
//! Clone the repository into local
//! - cd repo
//! - cargo test
//! - cargo bench

extern crate libc;
extern crate rustc_serialize as serialize;

use libc::{c_char, c_void};

#[link(name = "cryptonight")]
extern "C" {
    pub fn cn_slow_hash(
        data: *const c_void,
        length: usize,
        hash: *const c_char,
        variant: i32,
        pre_hashed: i32,
    ) -> c_void;
    pub fn set_params(m: u64, i: u64) -> c_void;
}

/// Computes the hash of <data> (which consists of <size> bytes), returning the hash (32 bytes).
/// # Arguments
/// * `data` - the data to hash
/// * `size` - the size in bytes of data
/// * `variant` - 1: Monero v7, 0: Monero V0
/// # Example
///
/// ```rust
/// # extern crate rustc_serialize as serialize;
/// # extern crate cryptonight;
/// # use cryptonight::cryptonight;
/// # use serialize::hex::FromHex;
/// struct Test {
///     input: Vec<u8>,
///     output: Vec<u8>,
///     variant: i32,
/// }
/// let test = Test{
/// input:"38274c97c45a172cfc97679870422e3a1ab0784960c60514d81627141\
/// 5c306ee3a3ed1a77e31f6a885c3cb".from_hex().unwrap(),
/// output:"ed082e49dbd5bbe34a3726a0d1dad981146062b39d36d62c71eb1ed8\
/// ab49459b".from_hex().unwrap(),
/// variant:1
/// };
/// let out = cryptonight(&test.input[..], test.input.len(), test.variant);
/// assert_eq!(out, test.output);
/// ```
///
/// # Reference
/// [https://cryptonote.org/cns/cns008.txt](https://cryptonote.org/cns/cns008.txt)
pub fn cryptonight(data: &[u8], size: usize, variant: i32) -> Vec<u8> {
    let hash: Vec<i8> = vec![0i8; 32];
    let data_ptr: *const c_void = data.as_ptr() as *const c_void;
    let hash_ptr: *const c_char = hash.as_ptr() as *const c_char;
    unsafe {
        cn_slow_hash(data_ptr, size, hash_ptr, variant, 0);
        std::mem::transmute::<Vec<i8>, Vec<u8>>(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serialize::hex::FromHex;

    struct Test {
        input: Vec<u8>,
        output: Vec<u8>,
        variant: i32,
    }

    /// totally 16 test cases
    fn test_hash(tests: &[Test]) {
        for t in tests {
            let out = cryptonight(&t.input[..], t.input.len(), t.variant);
            for x in out {
                println!("{}", x);
            }
        }
    }

    #[test]
    fn run_test() {
        let tests = vec![
            // from https://github.com/ExcitableAardvark/node-cryptonight/blob/master/index.test.js
            Test {
                input: "This is a test which as at least 43 bytes ..."
                    .as_bytes()
                    .to_vec(),
                output: "bf1b87e049bfe1c668c44f2dc1bb689a\
                         bcc729a704fc8088917cfbca202fc3cb"
                    .from_hex()
                    .unwrap(),
                variant: 1,
            },
            // from https://github.com/monero-project/monero/blob/0683f3190d09001fe3690613f796a0de0c4cee4c/tests/hash/tests-slow-1.txt @17th of August, 2018
            Test {
                input: "38274c97c45a172cfc97679870422e3a1ab0784960c\
                        60514d816271415c306ee3a3ed1a77e31f6a885c3cb"
                    .from_hex()
                    .unwrap(),
                output: "ed082e49dbd5bbe34a3726a0d1dad981\
                         146062b39d36d62c71eb1ed8ab49459b"
                    .from_hex()
                    .unwrap(),
                variant: 1,
            },
            Test {
                input: "37a636d7dafdf259b7287eddca2f5809\
                        9e98619d2f99bdb8969d7b14498102cc\
                        065201c8be90bd777323f449848b215d\
                        2977c92c4c1c2da36ab46b2e389689ed\
                        97c18fec08cd3b03235c5e4c62a37ad8\
                        8c7b67932495a71090e85dd4020a9300"
                    .from_hex()
                    .unwrap(),
                output: "613e638505ba1fd05f428d5c9f8e08f8\
                         165614342dac419adc6a47dce257eb3e"
                    .from_hex()
                    .unwrap(),
                variant: 1,
            },
            Test {
                input: "8519e039172b0d70e5ca7b3383d6b316\
                        7315a422747b73f019cf9528f0fde341\
                        fd0f2a63030ba6450525cf6de3183766\
                        9af6f1df8131faf50aaab8d3a7405589"
                    .from_hex()
                    .unwrap(),
                output: "5bb40c5880cef2f739bdb6aaaf16161e\
                         aae55530e7b10d7ea996b751a299e949"
                    .from_hex()
                    .unwrap(),
                variant: 1,
            },
            Test {
                input: "00000000000000000000000000000000000000\
                        00000000000000000000000000000000000000\
                        00000000000000000000000000000000000000\
                        00000000000000000000000000000000000000"
                    .from_hex()
                    .unwrap(),
                output: "80563c40ed46575a9e44820d93ee095e\
                         2851aa22483fd67837118c6cd951ba61"
                    .from_hex()
                    .unwrap(),
                variant: 1,
            },
            Test {
                input: "0000000000000000000000000000000000000000000\
                        0000000000000000000000000000000000000000000"
                    .from_hex()
                    .unwrap(),
                output: "b5a7f63abb94d07d1a6445c36c07c7e8\
                         327fe61b1647e391b4c7edae5de57a3d"
                    .from_hex()
                    .unwrap(),
                variant: 1,
            },
            // from https://github.com/monero-project/monero/blob/b780cf4db1f9dfc49e7f16afc47892a5b40fe68a/tests/hash/tests-slow.txt @17th of August, 2018
            Test {
                input: "6465206f6d6e69627573206475626974616e64756d"
                    .from_hex()
                    .unwrap(),
                output: "2f8e3df40bd11f9ac90c743ca8e32bb3\
                         91da4fb98612aa3b6cdc639ee00b31f5"
                    .from_hex()
                    .unwrap(),
                variant: 0,
            },
            Test {
                input: "6162756e64616e732063617574656c61206e6f6e206e6f636574"
                    .from_hex()
                    .unwrap(),
                output: "722fa8ccd594d40e4a41f3822734304c\
                         8d5eff7e1b528408e2229da38ba553c4"
                    .from_hex()
                    .unwrap(),
                variant: 0,
            },
            Test {
                input: "63617665617420656d70746f72".from_hex().unwrap(),
                output: "bbec2cacf69866a8e740380fe7b818fc\
                         78f8571221742d729d9d02d7f8989b87"
                    .from_hex()
                    .unwrap(),
                variant: 0,
            },
            Test {
                input: "6578206e6968696c6f206e6968696c20666974".from_hex().unwrap(),
                output: "b1257de4efc5ce28c6b40ceb1c6c8f81\
                         2a64634eb3e81c5220bee9b2b76a6f05"
                    .from_hex()
                    .unwrap(),
                variant: 0,
            },
            // from https://github.com/MoneroOcean/node-cryptonight-hashing/blob/af648e0c699af40a6a2415d91dc71deafaa55a90/tests/cryptonight.txt @17th of August, 2018
            Test {
                input: "Lorem ipsum dolor sit amet, consectetur ad\
                        ipiscing elit. Vivamus pellentesque metus."
                    .as_bytes()
                    .to_vec(),
                output: "0bbe54bd26caa92a1d436eec71cbef02\
                         560062fa689fe14d7efcf42566b411cf"
                    .from_hex()
                    .unwrap(),
                variant: 0,
            },
            Test {
                input: "ex nihilo nihil fit".as_bytes().to_vec(),
                output: "b1257de4efc5ce28c6b40ceb1c6c8f81\
                         2a64634eb3e81c5220bee9b2b76a6f05"
                    .from_hex()
                    .unwrap(),
                variant: 0,
            },
            Test {
                input: "caveat emptor".as_bytes().to_vec(),
                output: "bbec2cacf69866a8e740380fe7b818fc\
                         78f8571221742d729d9d02d7f8989b87"
                    .from_hex()
                    .unwrap(),
                variant: 0,
            },
            Test {
                input: "abundans cautela non nocet".as_bytes().to_vec(),
                output: "722fa8ccd594d40e4a41f3822734304c\
                         8d5eff7e1b528408e2229da38ba553c4"
                    .from_hex()
                    .unwrap(),
                variant: 0,
            },
            Test {
                input: "de omnibus dubitandum".as_bytes().to_vec(),
                output: "2f8e3df40bd11f9ac90c743ca8e32bb3\
                         91da4fb98612aa3b6cdc639ee00b31f5"
                    .from_hex()
                    .unwrap(),
                variant: 0,
            },
            Test {
                input: "This is a test".as_bytes().to_vec(),
                output: "a084f01d1437a09c6985401b60d43554\
                         ae105802c5f5d8a9b3253649c0be6605"
                    .from_hex()
                    .unwrap(),
                variant: 0,
            },
        ];
        test_hash(&tests[..]);
    }
}
