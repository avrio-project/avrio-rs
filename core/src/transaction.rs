use serde::{Deserialize, Serialize};
extern crate crypto;
extern crate database;

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

#[derive(Serialize, Deserialize, Debug)]
pub struct TxStore {
    // remove data not needed to be stored
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

impl Transaction {
    fn coinbase(tx: Transaction) -> bool {
        if tx.senderKey == "" {
            if validateSignature(tx.receive_key, tx.signature) {
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    fn typeTransaction(&self) -> String {
        return match (self.extra) {
            "" => "normal",
            "r" => "reward",
            "fnr" => "fullnode registration",
            "unr" => "username registraion",
            "l" => "fund lock",
            "b" => "burn",
            _ => "message",
        };
    }

    fn validateTransaction(&self) -> bool {
        let mut acc = getAccount(self.sender_key);
        if acc.balance == 0 {
            return false;
        }
        if self.amount < 0.0001 {
            // the min amount sendable (1 miao)
            return false;
        }
        if self.access_key != sender_key {
            if acc.balance < self.amount {
                return false;
            } else {
                if checkSignature() {
                    return true;
                }
            }
        }
    }
}

impl Hashable for Transaction {
    // TXN CREATION 101: run this then do tx.hash(); then sign the hash provided
    fn bytes(&self) -> Vec<u8> {
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
