//use avrio_config::config;
use avrio_crypto::{generate_keypair, raw_hash, Hashable};
use log::*;
use serde::{Deserialize, Serialize};
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Comitee {
    pub index: u64,
    pub members: Vec<String>,
    pub hash: String,
}
pub fn sort_full_list(full_list: &mut Vec<String>, epoch_salt: u64) {
    full_list.sort_by(|a, b| {
        raw_hash(&(a.clone() + &epoch_salt.to_string()))
            .cmp(&raw_hash(&(b.clone() + &epoch_salt.to_string())))
    }); // sort the inital vector alphabeticly but with the node's pubkey hashed with epoch salt to give some dermanistic randomness
}
impl Comitee {
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

    pub fn get_round_leader(&self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(self.members[0].clone()) // TODO Implment round leader selection algo
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
