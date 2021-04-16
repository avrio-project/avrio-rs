use crate::*;
#[test]
fn find_average_lambda() {
    let n = 50; // total number of candidates
    for r_target in 0..n {
        let mut tries = 0;
        loop {
            let mut entries: Vec<BigDecimal> = vec![];
            let mut amount_this_try = 0;
            for attempt in 0..n {
                let wall: Wallet = Wallet::gen();
                let (_, hash) =
                    get_vrf(wall.private_key.clone(), "epochrandomnesshere".to_string()).unwrap();
                let int_vrf = vrf_hash_to_integer(hash);
                entries.push(int_vrf.clone());
                if int_vrf < (BigDecimal::from(r_target) / BigDecimal::from(n)) {
                    println!(
                        "Attempt {}, value: {} < {}",
                        attempt,
                        int_vrf,
                        r_target as f64 / n as f64
                    );
                    amount_this_try += 1;
                }
            }
            tries += 1;
            if amount_this_try > 2 {
                println!(
                    "Took {} tries ({} target {})",
                    tries, amount_this_try, r_target
                );
                break;
            }
        }
        
    }
}

#[test]
fn test_max() {
    println!(
        "{}",
        vrf_hash_to_integer("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ".to_string())
    );
}
