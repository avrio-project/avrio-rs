//use avrio_config::config;
use avrio_crypto::{generate_keypair, raw_hash, Hashable, vrf_hash_to_u64};
use avrio_database::get_data;
use bigdecimal::BigDecimal;
use log::*;
use serde::{Deserialize, Serialize};
use std::ops::RangeInclusive;

use crate::epoch::get_top_epoch;
#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Comitee {
    pub index: u64,
    pub members: Vec<String>,
    pub hash: String,
}
pub fn sort_full_list(full_list: &mut Vec<String>, epoch_salt: u64) {
    // TODO: Fisher-yates shuffle
    full_list.sort_by(|a, b| {
        raw_hash(&(a.clone() + &epoch_salt.to_string()))
            .cmp(&raw_hash(&(b.clone() + &epoch_salt.to_string())))
    }); // sort the inital vector alphabeticly but with the node's pubkey hashed with epoch salt to give some dermanistic randomness
}
impl Comitee {
    /// # Calculate address range
    /// calculates the address range of this commitee (given the number of commitees) using:
    /// commitee_index *((58^44)/(commitee_number-1))..=*((58^44)/(commitee_number-1))-((commitee_number-commite_index)*((58^44)/(commitee_number-1)))
    pub fn calculate_address_range(&self, number_of_committees: u64) -> RangeInclusive<BigDecimal> {
        // We know there are 58^44 (389790920000000000000000000000000000000000000000000000000000000000000000000000) diffrent posible publickeys (base58 with len of 44), so the number of addresses per shard = (58^44)/(k-1)
        // k = total number (including 0 committee hence the - 1) of committees
        // to figure out the address space for comitee n (n = 0 means commitee 1, n = 1 means commitee 2 etc as we ignore the consensus comitee) you just do:
        // n*((58^44)/(k-1))..=*((58^44)/(k-1))-((k-n)*((58^44)/(k-1)))
        // if you let j = (58^44)/(k-1) this can simply be written as:
        //nj..=j-(j(k-(n+1)))
        let k = BigDecimal::from(number_of_committees - 1);
        let j = BigDecimal::from(58 ^ 44) / k.clone(); // not a decimal but bigdecimal works to store large integers too
        if self.index != 0 {
            let n = BigDecimal::from(self.index - 1);
            n * j.clone()..=j.clone() - (j * (k - BigDecimal::from(self.index)))
        } else {
            BigDecimal::from(0)..=BigDecimal::from(0)
        }
    }
    /// # Manages Address
    /// Checks if this committee manages a given address
    pub fn manages_address(&self, address: &String) -> Result<bool, Box<dyn std::error::Error>> {
        if self.index == 0 {
            return Ok(false);
        }
        let address_hex = hex::encode(bs58::decode(address).into_vec()?);
        let address_numerical = i64::from_str_radix(&address_hex, 16)?.abs();
        let address_bigdec = BigDecimal::from(address_numerical);
        Ok(self.calculate_address_range(2).contains(&address_bigdec)) // TODO: get the number of commitees (or pass as a parmeter)
    }
    /// # Form Committees
    /// Forms the commiitees given a list of shuffled nodes, as well as mutable refrence to the vector where excluded nodes are placed and a number (of commitees to be formed)
    /// Returns a vector of committess which it's length should be count - 1
    pub fn form_comitees(
        sorted_list: &mut Vec<String>,
        excluded_nodes: &mut Vec<String>,
        count: u64,
    ) -> Vec<Comitee> {
        loop {
            if sorted_list.len() % count as usize != 0 {
                if let Some(exclued) = sorted_list.pop() {
                    info!(
                        "Excluded fullnode {} from epoch (comitee overflow)",
                        exclued
                    );
                    excluded_nodes.push(exclued);
                } else {
                    error!("Tried to exclude top node from sorted_list by returned a None value");
                }
            } else {
                break;
            }
        }
        if excluded_nodes.len() != 0 {
            debug!(
                "Had to exclude {} fullnodes from epoch to fit",
                excluded_nodes.len()
            );
        }
        let comitee_size = sorted_list.len() / count as usize;
        info!(
            "Comitee count for epoch: {}, comitee size={}",
            count, comitee_size
        );
        let mut to_return: Vec<Comitee> = vec![];
        let mut to_assign = sorted_list.clone();
        for comitee_index in 0..count {
            let mut formed_comitee = Comitee {
                index: comitee_index,
                members: vec![],
                hash: String::from(""),
            };
            while formed_comitee.members.len() != comitee_size {
                if let Some(top_node) = to_assign.pop() {
                    debug!("Assigned {} to comitee {}", top_node, comitee_index);
                    formed_comitee.members.push(top_node);
                }
            }
            formed_comitee.hash = formed_comitee.hash_item();
            debug!(
                "Finished forming comitee {} (index: {})",
                formed_comitee.hash, comitee_index
            );
            to_return.push(formed_comitee);
        }
        return to_return;
    }

    /// # Get round leader
    /// Calculates the round leader for this committee, returning the ECDSA publickey or an error
    pub fn get_round_leader(&self) -> Result<String, Box<dyn std::error::Error>> {
        let epoch = get_top_epoch()?;
        let round = self.round().unwrap_or(0);
        let block_chunk =
            crate::chunk::BlockChunk::get_by_round(round, epoch.epoch_number, self.index).unwrap_or_default();
        let hash_string = raw_hash(&format!(
            "{}{}{}{}",
            round,
            block_chunk.hash,
            block_chunk.proposer()?,
            epoch.epoch_number
        ));
        let hash_hex = hex::encode(bs58::decode(&hash_string).into_vec()?);
        let hash_int = vrf_hash_to_u64(hash_hex.clone())?;

        let mut smallest_member = u64::MAX;
        let mut chosen_member: Option<String> = None;
        

        for member in &self.members {
            let pk_hex = hex::encode(bs58::decode(&member).into_vec()?);
            let pk_int = vrf_hash_to_u64(pk_hex)?;
            let diff: u64;
            if pk_int < hash_int {
                diff = hash_int - pk_int;
            } else {
                diff = pk_int - hash_int;
            }
            
            if diff < smallest_member {
                smallest_member = diff;
                chosen_member = Some(member.clone());
            }
        }

        if chosen_member == None {
            error!("Failed to choose round leader out of {} members, hash={}, hash_hex={}, hash_int={}, smallest_member={}", self.members.len(), hash_string, hash_hex, hash_int, smallest_member);
            return Err(format!("Failed to choose round leader out of {} members, hash={}, hash_hex={}, hash_int={}, smallest_member={}", self.members.len(), hash_string, hash_hex, hash_int, smallest_member).into());
        }
        let chosen_member = chosen_member.unwrap();
        trace!("Chosen {}, closest to {} (int: {})", chosen_member, hash_string, hash_int);
        
        Ok(chosen_member)
    }

    pub fn round(&self) -> Result<u64, Box<dyn std::error::Error>> {
        let top_epoch = get_top_epoch()?;
        let read = get_data(
            avrio_config::config().db_path + "/blockchunks",
            &(self.index.to_string() + "-round-" + &top_epoch.epoch_number.to_string()),
        );
        if read == "-1" {
            return Err("Round cannot be found".into());
        }
        return Ok(read.parse().unwrap());
    }
    /// Find the commitee publickey belongs to and returns its index, or None if it is not in one
    pub fn find_for(publickey: &String) -> Option<u64> {
        // finds the commitee publickey belongs to using a linear search
        for committee in get_top_epoch().unwrap_or_default().committees {
            if committee.members.contains(publickey) {
                return Some(committee.index);
            }
        }
        None
    }
}

impl Hashable for Comitee {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend(self.index.to_string().as_bytes());
        for member in &self.members {
            bytes.extend(member.as_bytes());
        }
        bytes
    }
}

// TESTS
#[test]
fn test_list_ordering() {
    let _ = simple_logger::init();
    let mut keypairs: Vec<String> = vec![];
    for _ in 0..100 {
        keypairs.push(generate_keypair().public_key);
    }
    let epoch_salt = 12345;
    let other_salt = 12346;

    let mut keypairs_rep = keypairs.clone();
    let mut diffrent_salt = keypairs.clone();
    println!("Unsorted: {:#?}", keypairs);
    sort_full_list(&mut keypairs, epoch_salt); // mutates keypairs
    println!("After sort: {:#?}", keypairs);
    for entry in &keypairs {
        assert!(keypairs_rep.contains(entry)); // make sure the public keys have not changed values (only order)
    }
    sort_full_list(&mut diffrent_salt, other_salt); // mutates diffrent_salt
    println!("With diffrent salt: {:#?}", diffrent_salt);
    assert_ne!(keypairs, diffrent_salt);
    sort_full_list(&mut keypairs_rep, epoch_salt); // mutates keypairs_rep
    assert_eq!(keypairs, keypairs_rep)
}
#[test]
fn test_comitee_formation() {
    let _ = simple_logger::init();
    let mut keypairs: Vec<String> = vec![];
    for _ in 0..100 {
        keypairs.push(generate_keypair().public_key);
    }
    let epoch_salt = 12345;
    sort_full_list(&mut keypairs, epoch_salt); // mutates keypairs
    let mut excluded_nodes: Vec<String> = vec![];
    //try with 0 excluded nodes expected
    let comitees = Comitee::form_comitees(&mut keypairs, &mut excluded_nodes, 10);
    assert!(excluded_nodes.len() == 0);
    println!("First run comitees (c=10): {:#?}", comitees);
    //try with excluded nodes expected
    let comitees = Comitee::form_comitees(&mut keypairs, &mut excluded_nodes, 9);
    println!("Seccond run comitees (c=9): {:#?}", comitees);
    println!("Excluded={}", excluded_nodes.len());
    assert!(excluded_nodes.len() != 0);
}
