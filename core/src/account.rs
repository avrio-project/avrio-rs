extern crate avrio_database;

use serde::{Deserialize, Serialize};
extern crate avrio_config;
use avrio_config::config;
use std::convert::TryInto;
use std::fs::File;
use std::io::prelude::*;
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct Accesskey {
    // Access keys are keys that provide limited access to a wallet - it allows one wallet to be split
    pub key: String, // into many. You can also code to the key indicating what the account can and cant do.
    pub allowance: u64,
    pub code: String,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
/// A account is a representaion of a wallet - it includes balance, a public
pub struct Account {
    /// key (which is used as a index for storing) and the list of access keys.
    pub public_key: String,
    pub username: String,
    pub balance: u64,
    pub locked: u64,
    pub level: u8,
    pub access_keys: Vec<Accesskey>,
}

pub fn to_atomc(amount: f64) -> u64 {
    (amount * (10_i64.pow(config().decimal_places as u32) as f64)) as u64
}

pub fn to_dec(amount: u64) -> f64 {
    amount as f64 / (10_i64.pow(config().decimal_places as u32)) as f64
}

impl Account {
    /// Used to get the blance of an account in decimal form not atomic (eg 0.3452 AIO or 345.2)
    pub fn balance_ui(&self) -> Result<f64, Box<dyn std::error::Error>> {
        Ok(to_dec(self.balance))
    }
    pub fn save(&self) -> Result<(), &str> {
        if set_account(self) == 0 {
            Err("Something went wrong")
        } else {
            Ok(())
        }
    }
    pub fn new(public_key: String) -> Account {
        // allows Account::new(publicKey)
        let acc: Account = Account {
            public_key,
            username: "".to_string(),
            balance: 0,
            locked: 0,
            level: 0,
            access_keys: vec![Accesskey {
                key: String::from(""),
                allowance: 0,
                code: String::from(""),
            }],
        };
        acc
    }

    pub fn add_username(&mut self, user_name: String) -> Result<(), &str> {
        self.username = user_name;
        self.save()
    }

    pub fn add_access_code(&mut self, perm_code: &str, pub_key: &str) -> Result<(), &str> {
        let new_acc_key: Accesskey = Accesskey {
            key: pub_key.to_owned(),
            allowance: 0,
            code: perm_code.to_owned(),
        };
        self.access_keys.push(new_acc_key);
        self.save()
    }
}
/// Gets the account assosiated with the username provided
/// if the account or the username does not exist it returns an err
pub fn get_by_username(username: &str) -> Result<Account, String> {
    let path =
        config().db_path + &"/usernames/".to_owned() + &avrio_crypto::raw_hash(username) + ".uname";
    if let Ok(mut file) = File::open(path) {
        let mut contents = String::new();
        let _ = file.read_to_string(&mut contents);
        Ok(get_account(&contents).unwrap_or_default())
    } else {
        Err("failed to open file".to_owned())
    }
}

pub fn set_account(acc: &Account) -> u8 {
    let path = config().db_path + "/accounts/" + &acc.public_key + ".account";
    let serialized: String;
    let get_acc_old = get_account(&acc.public_key);
    if let Ok(deserialized) = get_acc_old {
        if acc.username != deserialized.username && deserialized != Account::default() {
            let upath = config().db_path
                + &"/usernames/".to_owned()
                + &avrio_crypto::raw_hash(&acc.username)
                + ".uname";
            info!("saving uname: {}.", deserialized.username);
            let filetry = File::create(upath);
            if let Ok(mut file) = filetry {
                if file.write_all(&acc.public_key.as_bytes()).is_err() {
                    return 0;
                }
            } else {
                error!(
                    "Failed to save username, creating file gave error: {}",
                    filetry.unwrap_err(),
                );
                return 0;
            }
        }
    }
    serialized = serde_json::to_string(&acc).unwrap_or_else(|e| {
        error!("Unable To Serilise Account, gave error {}, retrying", e);
        serde_json::to_string(&acc).unwrap_or_else(|et| {
            error!("Retry Failed with error: {}", et);
            panic!("Failed to serilise account");
        })
    });
    let filetry = File::create(path);
    if let Ok(mut file) = filetry {
        if file.write_all(&serialized.as_bytes()).is_err() {
            return 0;
        }
    } else {
        error!(
            "Failed to save account, creating file gave error: {}",
            filetry.unwrap_err(),
        );
        return 0;
    }
    1
}
/// Gets the account assosiated with the public_key provided
/// if the account does not exist it returns an err
pub fn get_account(public_key: &str) -> Result<Account, u8> {
    let path = config().db_path + &"/accounts/".to_owned() + public_key + ".account";
    if let Ok(mut file) = File::open(path) {
        let mut contents = String::new();
        let _ = file.read_to_string(&mut contents);
        if let Ok(acc) = serde_json::from_str(&contents) {
            Ok(acc)
        } else {
            Err(2)
        }
    } else {
        Err(0)
    }
}

pub fn open_or_create(public_key: &str) -> Account {
    if let Ok(acc) = get_account(public_key) {
        acc
    } else if let Ok(acc) = get_by_username(public_key) {
        acc
    } else {
        let acc = Account::new(public_key.to_string());
        let _ = set_account(&acc);
        acc
    }
}

pub fn delta_funds(
    public_key: &str,
    amount: u64,
    mode: u8,
    access_key: String,
) -> Result<(), String> {
    let mut acc: Account = get_account(public_key).unwrap_or_else(|e| {
        debug!(
            "failed to get account with public key {}, gave error {}",
            public_key, e
        );
        Account::default()
    });
    if acc.public_key.is_empty() {
        return Err("Failed to get account".into());
    }
    if mode == 0 {
        // minus funds
        if access_key.is_empty() {
            // none provdied/ using main key
            if acc.balance < amount {
                // insufffient funds
                warn!(
                    "changing funds for account {} would produce negative balance!",
                    acc.public_key
                );
                Err("changing funds for account {} would produce negative balance".to_string())
            } else {
                acc.balance -= amount;
                match set_account(&acc) {
                    1 => Ok(()),
                    _ => Err("failed to set account".to_string()),
                }
            }
        } else {
            // access key provided
            let accesskeys = acc.access_keys.clone();
            let mut accesskey: Accesskey = Accesskey::default();
            let mut i = 0;
            while accesskey.key != access_key {
                accesskey = accesskeys[i].clone();
                i += 1;
            }
            if accesskey.key != access_key {
                // account does not have that access key
                warn!("changing funds for account {} with access key {}. Access key does not exist in context to account !", acc.public_key, access_key);
                Err("Access Key Does not exist".to_string())
            } else {
                let after_change: i64 = (acc.access_keys[i].allowance - amount).try_into().unwrap();
                if after_change < 0 {
                    // can access key allowance cover this?
                    warn!("changing funds for account {} with access key {:?} would produce negative allowance!",acc.public_key, access_key);
                    Err("changing funds for account with access key would produce negative allowance".to_string())
                } else {
                    acc.balance -= amount;
                    acc.access_keys[i].allowance -= amount;
                    match set_account(&acc) {
                        1 => Ok(()),
                        _ => Err("Failed to save account".to_string()),
                    }
                }
            }
        }
    } else {
        // add funds
        if access_key.is_empty() {
            // none provdied/ using main key
            acc.balance += amount;
            match set_account(&acc) {
                1 => Ok(()),
                _ => Err("Failed to save account".to_string()),
            }
        } else {
            let accesskeys = acc.access_keys.clone();
            let mut accesskey = Accesskey::default();
            let mut i = 0;
            while accesskey.key != access_key {
                accesskey = accesskeys[i].clone();
                i += 1;
            }
            if accesskey.key != access_key {
                // account does not have that access key
                warn!("changing funds for account {} with access key {}. Access key does not exist in context to account!", acc.public_key, access_key);
                Err("Access Key does not exist".to_string())
            } else {
                acc.access_keys[i].allowance += amount;
                acc.balance += amount;
                match set_account(&acc) {
                    1 => Ok(()),
                    _ => Err("Failed to save account".to_string()),
                }
            }
        }
    }
}
