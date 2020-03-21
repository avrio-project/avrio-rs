extern crate avrio_database;
use avrio_database::{getData, saveData};
use serde::{Deserialize, Serialize};
extern crate avrio_config;
use avrio_config::config;
use std::process::exit;

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct Accesskey {
    // Access keys are keys that provide limited access to a wallet - it allows one wallet to be split
    pub key: String, // into many. You can also code to the key indicating what the account can and cant do.
    pub allowance: u64,
    pub code: String,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct Account {
    // A account is a representaion of a wallet - it includes balance, a public
    pub public_key: String, // key (which is used as a index for storing) and the list of access keys.
    pub username: String,
    pub balance: u64,
    pub locked: u64,
    pub access_keys: Vec<Accesskey>,
}

impl Account {
    pub fn save(&self) -> Result<(), ()> {
        match setAccount(self) {
            0 => {
                return Err(());
            }
            1 => {
                return Ok(());
            }
            _ => {
                return Err(());
            }
        };
    }
    pub fn new(publicKey: String) -> Account {
        // allows Account::new(publicKey)
        let acc: Account = Account {
            public_key: publicKey,
            username: "".to_string(),
            balance: 0,
            locked: 0,
            access_keys: vec![Accesskey {
                key: String::from(""),
                allowance: 0,
                code: String::from(""),
            }],
        };
        return acc;
    }
    pub fn addUsername(&mut self, userName: String) -> Result<(), ()> {
        self.username = userName;
        return Ok(());
    }
    pub fn addAccessCode(&mut self, permCode: &String, pubKey: &String) -> Result<(), ()> {
        let new_acc_key: Accesskey = Accesskey {
            key: pubKey.to_owned(),
            allowance: 0,
            code: permCode.to_owned(),
        };
        self.access_keys.push(new_acc_key);
        return Ok(());
    }
}
/// Gets the account assosiated with the username provided
/// if the account or the username does not exist it returns an err
pub fn getByUsername(username: &String) -> Result<Account, String> {
    let publicKey: String = getData(config().db_path + &"/usernamedb".to_string(), username);
    if let Ok(acc) = getAccount(&publicKey) {
        return Ok(acc);
    } else {
        return Err("failed to read account".into());
    }
}

pub fn setAccount(acc: &Account) -> u8 {
    let path = config().db_path + "/db/accountdb";
    let serialized: String;
    serialized = serde_json::to_string(&acc).unwrap_or_else(|e| {
        error!("Unable To Serilise Account, gave error {}, retrying", e);
        return serde_json::to_string(&acc).unwrap_or_else(|et| {
            error!("Retry Failed with error: {}", et);
            panic!("Failed to serilise account");
        });
    });
    saveData(serialized, path, acc.public_key.clone());
    return 1;
}
/// Gets the account assosiated with the public_key provided
/// if the account does not exist it returns an err
pub fn getAccount(public_key: &String) -> Result<Account, u8> {
    let path = config().db_path + &"/bd/accountdb".to_owned();
    let data = getData(path, public_key);
    if data == "-1" || data == "0" {
        return Err(1);
    } else {
        let acc: Account = serde_json::from_str(&data).unwrap_or_else(|e| {
            info!(
                "Failed to Parse Account {:?}, gave error {:?}, Retrying...",
                &data, e
            );
            return serde_json::from_str(&data).unwrap_or_else(|et| {
                error!("Retry failed with error {:?}", et);
                //process::exit(1);
                panic!();
            });
        });
        return Ok(acc);
    }
}

pub fn deltaFunds(
    public_key: &String,
    amount: u64,
    mode: u8,
    access_key: String,
) -> Result<(), String> {
    let mut acc: Account = getAccount(public_key).unwrap_or_else(|e| {
        debug!(
            "failed to get account with public key {}, gave error {}",
            public_key, e
        );
        return Account::default();
    });
    if mode == 0 {
        // minus funds
        if access_key == "" {
            // none provdied/ using main key
            let after_change = acc.balance - amount;
            if after_change < 0 {
                // insufffient funds
                warn!(
                    "changing funds for account {} would produce negative balance!",
                    acc.public_key
                );
                return Err(
                    "changing funds for account {} would produce negative balance".to_string(),
                );
            } else {
                acc.balance = acc.balance - amount;
                return match setAccount(&acc) {
                    1 => Ok(()),
                    _ => Err("failed to set account".to_string()),
                };
            }
        } else {
            // access key provided
            let accesskeys = acc.access_keys.clone();
            let mut accesskey: Accesskey = Accesskey::default();
            let mut i = 0;
            while accesskey.key != access_key {
                accesskey = accesskeys[i].clone();
                i = i + 1;
            }
            if accesskey.key != access_key {
                // account does not have that access key
                warn!("changing funds for account {} with access key {}. Access key does not exist in context to account !", acc.public_key, access_key);
                return Err("Access Key Does not exist".to_string());
            } else {
                let after_change = acc.access_keys[i].allowance - amount;
                if after_change < 0 {
                    // can access key allowance cover this?
                    warn!("changing funds for account {} with access key {:?} would produce negative allowance!",acc.public_key, access_key);
                    return Err("changing funds for account with access key would produce negative allowance".to_string());
                } else {
                    acc.balance = acc.balance - amount;
                    acc.access_keys[i].allowance = acc.access_keys[i].allowance - amount;
                    return match setAccount(&acc) {
                        1 => Ok(()),
                        _ => Err("Failed to save account".to_string()),
                    };
                }
            }
        }
    } else {
        // add funds
        if access_key == "" {
            // none provdied/ using main key
            acc.balance = acc.balance + amount;
            return match setAccount(&acc) {
                1 => Ok(()),
                _ => Err("Failed to save account".to_string()),
            };
        } else {
            let accesskeys = acc.access_keys.clone();
            let mut accesskey = Accesskey::default();
            let mut i = 0;
            while accesskey.key != access_key {
                accesskey = accesskeys[i].clone();
                i = i + 1;
            }
            if accesskey.key != access_key {
                // account does not have that access key
                warn!("changing funds for account {} with access key {}. Access key does not exist in context to account!", acc.public_key, access_key);
                return Err("Access Key does not exist".to_string());
            } else {
                acc.access_keys[i].allowance = acc.access_keys[i].allowance + amount;
                acc.balance = acc.balance + amount;
                return match setAccount(&acc) {
                    1 => Ok(()),
                    _ => Err("Failed to save account".to_string()),
                };
            }
        }
    }
}
