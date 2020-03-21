extern crate hex;

#[macro_use]
extern crate bencher;
extern crate cryptonight;
use bencher::Bencher;
use cryptonight::cryptonight;

fn benchmark_print() {
    let INPUT_DATA: String =
        "0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9abce4fa912244500000000e"
            .to_string();
    unsafe {
        cryptonight::set_params(262144, 262144);
    }
    for i in -1..4 {
        let out = cryptonight(&INPUT_DATA.as_bytes(), INPUT_DATA.as_bytes().len(), i);
        let s = hex::encode(out);
        println!("varient: {} result: {}", i, s);
    }
}
fn benchmark_cryptonight_43_1(bench: &mut Bencher) {
    benchmark_print();
    let bytes = [1u8; 43];
    bench.iter(|| cryptonight(&bytes, bytes.len(), 1));
}

fn benchmark_cryptonight_1k_1(bench: &mut Bencher) {
    let bytes = [1u8; 1024];
    bench.iter(|| cryptonight(&bytes, bytes.len(), 1));
}

fn benchmark_cryptonight_64k_1(bench: &mut Bencher) {
    let bytes = [1u8; 65536];
    bench.iter(|| cryptonight(&bytes, bytes.len(), 1));
}

fn benchmark_cryptonight_43_0(bench: &mut Bencher) {
    let bytes = [1u8; 43];
    bench.iter(|| cryptonight(&bytes, bytes.len(), 0));
}

fn benchmark_cryptonight_1k_0(bench: &mut Bencher) {
    let bytes = [1u8; 1024];
    bench.iter(|| cryptonight(&bytes, bytes.len(), 0));
}

fn benchmark_cryptonight_64k_0(bench: &mut Bencher) {
    let bytes = [1u8; 65536];
    bench.iter(|| cryptonight(&bytes, bytes.len(), 0));
}

benchmark_group!(
    benches,
    benchmark_cryptonight_43_1 /*benchmark_cryptonight_1k_1,
                               benchmark_cryptonight_64k_1,
                               benchmark_cryptonight_43_0,
                               benchmark_cryptonight_1k_0,
                               benchmark_cryptonight_64k_0*/
);
benchmark_main!(benches);
