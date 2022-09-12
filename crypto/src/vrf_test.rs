


#[test]
fn find_average_lambda() {
    let n = 500; // total number of candidates
    for r_target in 1..n {
        let mut tries = 0;
        loop {
            let mut entries: Vec<u64> = vec![];
            let mut amount_this_try = 0;
            for _attempt in 0..n {
                let wall: Wallet = Wallet::gen();
                let (_, hash) =
                    get_vrf(wall.private_key.clone(), "epochrandomnesshere".to_string()).unwrap();
                let int_vrf = vrf_hash_to_u64(hash).unwrap();
                let val_vrf = normalize(int_vrf);
                entries.push(int_vrf.clone());
                if val_vrf < r_target as f64 / n as f64 {
                    // (BigDecimal::from(r_target) / BigDecimal::from(n)) {
                    /*println!(
                        "Attempt {}, value: {} < {} {}",
                        attempt,
                        val_vrf,
                        r_target as f64 / n as f64,
                        val_vrf < r_target as f64 / n as f64
                    );*/
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
#[test]
fn test_len() {
    let wall: Wallet = Wallet::gen();
    let (proof, hash) =
        get_vrf(wall.private_key.clone(), "epochrandomnesshere".to_string()).unwrap();
    println!(
        "Proof: {}, Hash: {}; len: {}, {}",
        proof,
        hash,
        proof.len(),
        hash.len()
    )
}

#[test]
fn test_valid() {
    let keys = generate_secp256k1_keypair();
    let (proof, hash) = get_vrf(keys[0].clone(), "epochrandomnesshere".to_string()).unwrap();
    let valid = validate_vrf(
        keys[1].clone(),
        proof.clone(),
        "epochrandomnesshere".to_string(),
    );
    println!("Proof: {}, Hash: {}; valid: {}", proof, hash, valid);
    assert!(valid);
}
#[test]
fn test_vrf_keys() {
    let keys = generate_secp256k1_keypair();
    let seckey = SecretKey::from_slice(&bs58::decode(&keys[0]).into_vec().unwrap()).unwrap();
    let _pubkey = PublicKey::from_slice(&bs58::decode(&keys[1]).into_vec().unwrap()).unwrap();

    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();

    let derived_public_key = vrf.derive_public_key(seckey.as_ref()).unwrap();
    assert_eq!(
        _pubkey.to_hex(),
        PublicKey::from_slice(&derived_public_key).unwrap().to_hex()
    );
}
