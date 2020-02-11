extern crate cc;

use cc::Build;

fn main() {
    Build::new()
        .include("src/vendor/crypto")
        .include("src/vendor/common")
        .file("src/vendor/aesb.c")
        .file("src/vendor/blake256.c")
        .file("src/vendor/chacha.c")
        .file("src/vendor/crypto-ops-data.c")
        .file("src/vendor/crypto-ops.c")
        .file("src/vendor/groestl.c")
        .file("src/vendor/hash-extra-blake.c")
        .file("src/vendor/hash-extra-groestl.c")
        .file("src/vendor/hash-extra-jh.c")
        .file("src/vendor/hash-extra-skein.c")
        .file("src/vendor/hash.c")
        .file("src/vendor/jh.c")
        .file("src/vendor/keccak.c")
        .file("src/vendor/oaes_lib.c")
        .file("src/vendor/skein.c")
        .file("src/vendor/slow-hash.c")
        .flag("-maes")
        .flag("-Ofast")
        .flag("-fexceptions")
        .compile("cryptonight")
}
