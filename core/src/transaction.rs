//
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Transaction {
    hash: String,
    amount: u64,
    extra: String,
    flag: char,
    sender_key: String,
    receive_key: String,
    access_key: String,
    gas_price: u64,
    max_gas: u64,
    gas: u64, // gas used
    nonce: u8,
    signature: String,
}
impl Hashable for Transaction { // TXN CREATION 101: run this then do tx.hash(); then sign the hash provided
    fn bytes (&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(self.ammount);
        bytes.extend(self.extra);
        bytes.extend(self.flag);
        bytes.extend(self.sender_key);
        bytes.extend(self.receive_key);
        bytes.extend(self.gas * self.gas_price); // aka fee
        bytes.extend(self.nonce);
        bytes
    }
}

fn hashTransaction(tx: Transaction) -> String {
    return tx.hash();
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TxStore { // remove data not needed to be stored
    hash: String,
    amount: u64,
    extra: String,
    sender_key: String,
    receive_key: String,
    access_key: String,
    fee: u64, // fee in AIO (gas_used * gas_price)
    nonce: u8,
    signature: String,
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
