use serde::{Serialize, Deserialize};
extern crate blockchain;

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
