use serde::{Serialize, Deserialize};
use database::{setAccount, getAccount};
extern crate blockchain;

#[derive(Serialize, Deserialize, Debug)]
pub struct Accesskey{ // Access keys are keys that provide limited access to a wallet - it allows one wallet to be split
  key: String,        // into many. You can also assign a code to the key indicating what the account can and cant do.
  allowance: u64,
  code: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Account {  // A account is a representaion of a wallet - it includes balance, a public 
  public_key: String, // key (which is used as a index for storing) and the list of access keys.
  balance: u64,
  access_keys: Vec<Accesskey>,
}

pub fn deltaFunds(public_key: String, amount: u64, mode: u8, access_key: String) -> bool {
  let mut acc = getAccount(public_key);
  if mode == 0 
  { // minus funds
    if access_key == ""
     { // none provdied/ using main key
      let after_change = acc.balance - amount;
      if after_change < 0 
      { // insufffient funds
        println!("ERROR: changing funds for account {} would produce negative balance!",acc.public_key);
        return false;
      } else 
      {
        acc.balance = acc.balance - amount;
        return setAccount(public_key,acc);
      }
    }else 
    { // access key provided
      let mut accesskey = acc.access_keys;
      let mut i = 0;
      while accesskey != access_key
      {
        accesskey = accesskey[i];
        i = i + 1;
      }
     if accesskey != access_key 
     { // account does not have that access key
        println!("ERROR: changing funds for account {0} with access key {1}. Access key does not exist in context to account {0}!", acc.public_key, access_key);
       return false;
     } else 
     {
       let after_change = acc.access_keys[i].allowance - amount;
       if after_change < 0 
       { // can access key allowance cover this?
         println!("ERROR: changing funds for account {0} with access key {1} would produce negative allowance!",acc.public_key, access_key);
          return false;
       } else 
       {
         acc.balance = acc.balance - amount;
          acc.access_keys[i].allowance = acc.access_keys[i].allowance - amount;
          return setAccount(public_key,acc);
       }
     }
    }
  } else 
  { // add funds 
    if access_key == "" { // none provdied/ using main key
      acc.balance = acc.balance + amount;
      return setAccount(public_key,acc);
     } else {
       let mut accesskey = acc.access_keys;
      let mut i = 0;
      while accesskey != access_key {
        accesskey = accesskey[i];
        i = i + 1;
      }
     if accesskey != access_key { // account does not have that access key
        println!("ERROR: changing funds for account {0} with access key {1}. Access key does not exist in context to account {0}!", acc.public_key, access_key);
       return 0;
     } else {
       acc.access_keys[i].allowance = acc.access_keys[i].allowance + amount;
       acc.balance = acc.balance + amount;
       return setAccount(public_key,acc);
     }
  }
 }
}

fn coinbase(tx: Transaction) -> bool {
    if tx.senderKey == "" {
        if validateSignature(tx.receive_key, tx.signature) {
            return true;
        }else return false;
    }else return false;
}
    
fn typeTransaction(tx: Transaction) -> String 
{
    return match(tx.extra)  {
        ""=>"normal",
        "r" => "reward",
        "fnr" => "fullnode registration",
        "unr" => "username registraion",
        "l" => "fund lock",
        "b" => "burn",
        _ => "message",
    };
} 
    
fn validateTransaction(tx: Transaction) -> bool {
    let mut acc = getAccount(tx.sender_key);
    if acc.balance == 0 {
        return false;
    }
    if tx.amount < 0.0001 { // the min amount sendable (1 miao)
        return false;
    }
    if tx.access_key != sender_key {
        if acc.balance < tx.amount {
            return false;
        }else {
            if checkSignature(){
              return true;
            }
        }
        
    }
}
}
