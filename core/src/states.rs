use crate::block::get_block;
use avrio_database::{get_data, open_database, save_data};

pub fn update_chain_digest(new_blk_hash: &str, cd_db: String, chain: &str) -> String {
    trace!(target: "blockchain::chain_digest","Updating chain digest for chain={}, hash={}", chain, new_blk_hash);
    let curr = get_data(cd_db.to_owned(), chain);
    let root: String;
    if &curr == "-1" {
        trace!(target: "blockchain::chain_digest","chain digest not set");
        root = avrio_crypto::raw_lyra(new_blk_hash);
    } else {
        trace!(target: "blockchain::chain_digest","Updating set chain digest. Curr: {}", curr);
        root = avrio_crypto::raw_lyra(&(curr + new_blk_hash));
    }
    let _ = save_data(&root, &cd_db, chain.to_owned());
    trace!(target: "blockchain::chain_digest","Chain digest for chain={} updated to {}", chain, root);
    root
}

/// takes a DB object of the chains digest (chaindigest) db and a vector of chain_keys (as strings) and calculates the chain digest for each chain.
/// It then sets the value of chain digest (for each chain) in the db, and returns it in the vector of strings
pub fn form_chain_digest(
    cd_db: String,
    chains: Vec<String>,
) -> std::result::Result<Vec<String>, Box<dyn std::error::Error>> {
    // TODO: do we need to return a Result<vec, err>? Cant we just return vec as there is no unwrapping needing to be done that could be replaced with the ? operator (and hence no chance of errors)?
    let mut output: Vec<String> = vec![];
    for chain in chains {
        trace!("Chain digest: starting chain={}", chain);
        // get the genesis block
        let genesis = get_block(&chain, 0);
        // hash the hash
        let mut temp_leaf = avrio_crypto::raw_lyra(&avrio_crypto::raw_lyra(&genesis.hash));
        // set curr_height to 1
        let mut curr_height: u64 = 1;
        loop {
            // loop through, increasing curr_height by one each time. Get block with height curr_height and hash its hash with the previous temp_leaf node. Once the block we read at curr_height
            // is Default (eg there is no block at that height), break from the loop
            let temp_block = get_block(&chain, curr_height);
            if temp_block.is_default() {
                break; // we have exceeded the last block, break/return from loop
            } else {
                temp_leaf = avrio_crypto::raw_lyra(&format!("{}{}", temp_leaf, temp_block.hash));
                trace!(
                    "Chain digest: chain={}, block={}, height={}, new temp_leaf={}",
                    chain,
                    temp_block.hash,
                    curr_height,
                    &temp_leaf
                );
                curr_height += 1;
            }
        }
        // we are finished, update the chain_digest on disk and add it to the output vector
        avrio_database::save_data(&temp_leaf, &cd_db, chain.to_owned());
        output.push(temp_leaf);
        trace!(
            "Chain digest: Finished chain={}, new output={:?}",
            chain,
            output
        );
    }
    // return the output vector
    Ok(output)
}

/// Calculates the 'overall' digest of the DAG.
/// Pass it a database object of the chaindigest database. This database should contain all the chains chain digests (with the key being the publickey)
/// as well as 'master' (as a key) being the state digest.
/// Run form_chain_digest(chain) (with chain being the publickey of the chain you want, or * for every chain) first which will form a chain digest
/// from scratch (or update_chain_digest(chain, new_block_hash, cd_db)). This function will return the new state digest as a string as well as update it in the database
///
pub fn form_state_digest(cd_db: String) -> std::result::Result<String, Box<dyn std::error::Error>> {
    debug!("Updating state digest");
    let start = std::time::Instant::now();
    let current_state_digest = get_data(cd_db.to_owned(), "master"); // get the current state digest, for refrence
    if &current_state_digest == "-1" {
        trace!("State digest not set");
    } else {
        trace!("Updating set state digest. Curr: {}", current_state_digest);
    }
    // we now recursivley loop through cd_db and add every value (other than master) to a vector
    // now we have every chain digest in a vector we sort it alphabeticly
    // now the vector of chain digests is sorted alphabeticly we recursivley hash them
    // like so: (TODO: use a merkle tree not a recursive hash chain)
    // leaf_one = hash(chain_digest_one + chain_digest_two)
    // leaf_two = hash(leaf_one + chain_digest_three)
    // leaf[n] = hash(leaf[n-1] + chain_digest[n+1])
    let mut _roots: Vec<(String, String)> = vec![]; // 0: chain_key, 1: chain_digest
                                                    //iter.seek_to_first();
    
    let _chains_list: Vec<String> = Vec::new();
    for (chain_key_string, chain_digest_string) in open_database(cd_db.to_owned())?.iter() {
        if chain_key_string != "master"
            && chain_key_string != "blockcount"
            && chain_key_string != "topblockhash"
        {
            _roots.push((chain_key_string.to_owned(), chain_digest_string.to_owned()));
        } else {
            log::trace!(
                "found {}:{} (key, value) in chaindigest database, ignoring",
                chain_key_string,
                chain_digest_string
            );
        }
    }
    let _rootsps = _roots.clone();
    _roots.sort_by(|a, b| a.1.to_lowercase().cmp(&b.1.to_lowercase())); // sort to aplabetical order (based on chain key)
    log::trace!(
        "Roots presort={:#?}, roots post sort={:#?}",
        _rootsps,
        _roots
    );
    drop(_rootsps);
    let mut temp_leaf: String;
    // create the first leaf
    if _roots.len() == 1 {
        temp_leaf = avrio_crypto::raw_lyra(&_roots[0].1.to_owned());
    } else if !_roots.is_empty() {
        temp_leaf = avrio_crypto::raw_lyra(&(_roots[0].1.to_owned() + &_roots[1].1)); // Hash the first two chain digests together to make the first leaf
        let cd_one = &_roots[0].1;
        let cd_two = &_roots[1].1;
        for (chain_string, digest_string) in _roots.clone() {
            // TODO: can we put _roots in a cow (std::borrow::Cow) to prevent cloning? (micro-optimisation)
            // check that digest_string is not the first two (which we already hashed)
            if &digest_string == cd_one || &digest_string == cd_two {
            } else {
                // hash digest_string with temp_leaf
                log::trace!(
                    "Chain digest: chain={}, chain_digest={}, current_tempory_leaf={}",
                    chain_string,
                    digest_string,
                    temp_leaf
                );
                temp_leaf = avrio_crypto::raw_lyra(&(digest_string + &temp_leaf));
            }
        }
        // we have gone through every digest and hashed them together, now we save to disk
    } else {
        temp_leaf = avrio_crypto::raw_lyra(&"".to_owned());
    }
    log::debug!(
        "Finished state digest calculation, old={}, new={}, time_to_complete={}",
        current_state_digest,
        temp_leaf,
        start.elapsed().as_millis()
    );
    avrio_database::save_data(&temp_leaf, &cd_db, "master".to_string());
    Ok(temp_leaf)
}
