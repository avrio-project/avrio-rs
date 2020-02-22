use database::{setData, getData};
use serde::{Deserialize, Serialize};
#[macro_use]
extern crate log;
extern crate config;
use config::config;

#[derive(Serialize, Deserialize, Debug)]
pub struct Accesskey {
    // Access keys are keys that provide limited access to a wallet - it allows one wallet to be split
    pub key: String, // into many. You can also code to the key indicating what the account can and cant do.
    pub allowance: u64,
    pub code: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Account {
    // A account is a representaion of a wallet - it includes balance, a public
    pub public_key: String, // key (which is used as a index for storing) and the list of access keys.
    pub balance: u64,
    pub access_keys: Vec<Accesskey>,
}

impl Account {
    fn new(publicKey: String) -> Account { // allows Account::new(publicKey)
        let mut acc: Account = Account {
            public_key: publicKey,
            balance: 0,
            access_keys: vec![Accesskey { key: String::from(""), allowance: 0, code: String::from("")}],
        };
        return acc;
    }
    fn addAccessCode(&mut self, permCode: &String, pubKey: &String) -> Result<(), ()> {
        let new_acc_key: Accesskey = Accesskey {
            key: pubKey.to_owned(),
            allowance: 0,
            code: permCode.to_owned(),
        };
        self.access_keys.push(new_acc_key);
        Ok(());
    }
}

fn setAccount(acc: Account) -> u8 {
    let path = config().db_path + "/db/accountdb";
    let serialized: String;
    serialized = serde_json::to_string(&acc).unwrap_or_else(|e| {
        error!("Unable To Serilise Account, gave error {}, retrying", e);
        serialized = serde_json::to_string(&acc).unwrap_or_else(|et| { 
                error!("Retry Failed with error: {}" et);
                panic!();
        });
    });
    saveData(serialized, path, acc.public_key);
    return 1;
}

fn getAccount(public_key: String) -> Result<Account, u8> {
    let path = config().db_path + "/bd/accountdb".to_owned();
    let mut data = getData(path, public_key);
    if data != "1" {
        return Err(1);
    } else {
        let acc: Account;
        acc = serde_json::from_str(&data).unwrap_or_else(|e| { 
            error!("Failed to Parse Account {:?}, gave error {:?}, Retrying...", &data, e);
            serde_json::from_str(&data).unwrap_or_else(|et| { 
                error!("Retry failed with error {:?}", et);
                panic!();
            });
        });
    }
    return Ok(acc);
}

pub fn deltaFunds(public_key: String, amount: u64, mode: u8, access_key: String) -> Result<(), String> {
    let mut acc = getAccount(public_key);
    if mode == 0 {
        // minus funds
        if access_key == "" {
            // none provdied/ using main key
            let after_change = acc.balance - amount;
            if after_change < 0 {
                // insufffient funds
                warn!("changing funds for account {} would produce negative balance!", acc.public_key);
                return Err("changing funds for account {} would produce negative balance");
            } else {
                acc.balance = acc.balance - amount;
                return setAccount(public_key, acc);
            }
        } else {
            // access key provided
            let mut accesskey = acc.access_keys;
            let mut i = 0;
            while accesskey != access_key {
                accesskey = accesskey[i];
                i = i + 1;
            }
            if accesskey != access_key {
                // account does not have that access key
                warn!("changing funds for account {} with access key {}. Access key does not exist in context to account !", acc.public_key, access_key);
                return Err("Access Key Does not exist");
            } else {
                let after_change = acc.access_keys[i].allowance - amount;
                if after_change < 0 {
                    // can access key allowance cover this?
                    warn!("changing funds for account {} with access key {} would produce negative allowance!",acc.public_key, access_key);
                    return Err("changing funds for account with access key would produce negative allowance");
                } else {
                    acc.balance = acc.balance - amount;
                    acc.access_keys[i].allowance = acc.access_keys[i].allowance - amount;
                    return setAccount(public_key, acc);
                }
            }
        }
    } else {
        // add funds
        if access_key == "" {
            // none provdied/ using main key
            acc.balance = acc.balance + amount;
            return setAccount(public_key, acc);
        } else {
            let mut accesskey = acc.access_keys;
            let mut i = 0;
            while accesskey != access_key {
                accesskey = accesskey[i];
                i = i + 1;
            }
            if accesskey != access_key {
                // account does not have that access key
                warn!("changing funds for account {} with access key {}. Access key does not exist in context to account!", acc.public_key, access_key);
                return Err("Access Key does not exist");
            } else {
                acc.access_keys[i].allowance = acc.access_keys[i].allowance + amount;
                acc.balance = acc.balance + amount;
                return setAccount(public_key, acc);
            }
        }
    }
}
