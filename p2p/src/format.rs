use avrio_crypto::raw_hash;
use bson;
use serde::{Deserialize, Serialize};

pub const LEN_DECL_BYTES: usize = 9; // 000 000 000
const CHECKSUM_BYTES: usize = 5;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct P2pData {
    len: usize,
    pub message_type: u16,
    pub message: String,
    checksum: String,
}
use log::debug;

/// # Pad len
/// Takes a usize and returns a strng that is LEN_DECL_BYTES long
pub fn pad_len(length: usize) -> String {
    let mut len_s: String = length.to_string();
    while len_s.len() != LEN_DECL_BYTES {
        len_s = format!("0{}", len_s);
    }
    return len_s;
}

impl P2pData {
    /// # Gen
    /// Takes a message and a type and returns a fully filled out P2pData struct
    pub fn gen(message: String, message_type: u16) -> P2pData {
        P2pData {
            checksum: raw_hash(&message)[0..CHECKSUM_BYTES].to_string(),
            len: message.len(),
            message_type,
            message,
        }
    }
    /// # Length
    /// Returns the length that will be appened on the end of a message.
    /// You must pad this value with the pad_len() method before appending to the end of your string
    pub fn length(&self) -> usize {
        self.message.len() + CHECKSUM_BYTES + LEN_DECL_BYTES
    }
    /// # Checksum
    /// Calculates the checksum of a message in P2pData
    pub fn checksum(&self) -> String {
        raw_hash(&self.message)[0..CHECKSUM_BYTES].to_string()
    }
    /// # to_string
    /// Takes a P2pData struct and turns it into a string that can be decoded on the other end of the stream
    pub fn to_string(&self) -> String {
        let s = match bson::to_bson(&self) {
            Ok(s) => s.to_string(),
            Err(e) => {
                debug!("Failed to encode P2pData to bson, gave error: {}", e);
                "error".to_string()
            }
        };
        let checksum: String = self.checksum();
        let len: usize = s.len() + CHECKSUM_BYTES + LEN_DECL_BYTES;
        let mut len_s: String = len.to_string();
        while len_s.len() != LEN_DECL_BYTES {
            len_s = format!("0{}", len_s);
        }
        return format!("{}{}{}{}", len_s, s, checksum, len_s);
    }
    /// # from_string
    /// Takes a string encoded P2pData (as outputed by to_string) and returns a P2pData struct
    /// On failure it will return a P2pData::default()
    pub fn from_string(s: &String) -> P2pData {
        let n = CHECKSUM_BYTES + LEN_DECL_BYTES;
        if s.len() <= n + LEN_DECL_BYTES {
            return P2pData::default();
        }
        let ser: String = s[LEN_DECL_BYTES - 1..s.len() - n].to_owned();
        let d: P2pData;
        match bson::from_bson(bson::to_bson(&ser).unwrap_or_default()) {
            Ok(p) => {
                d = p;
            }
            Err(e) => {
                debug!("Decoding bson to p2pdata struct gave error: {}", e);
                d = P2pData::default();
            }
        };
        let checksum = s[s.len() - CHECKSUM_BYTES..s.len()].to_owned();
        if checksum != d.checksum() {
            return P2pData::default();
        }
        return d;
    }
}
