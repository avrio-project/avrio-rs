use crate::{
    format::{P2pData, LEN_DECL_BYTES},
    peer::{strip_port, PEERS},
};
use log::{debug, trace};
use rust_crypto::{
    aead::{AeadDecryptor, AeadEncryptor},
    aes::KeySize,
    aes_gcm::AesGcm,
};
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;

const MAX_PEAK_BUFFER_SIZE: usize = 1000000; // 1 Mb, if the message is longer than this you cannot peak it. can be increased but should not need to be

pub fn peek(peer: &mut TcpStream) -> Result<usize, std::io::Error> {
    let mut buf = [0; MAX_PEAK_BUFFER_SIZE]; // create a buffer of MAX_BUFFER_SIZE 0s to peak into
    return peer.peek(&mut buf);
}

pub trait Sendable {
    /// # encode
    /// Should encode T into a String that can be transported and then decoded with the decode function
    fn encode(&self) -> Result<String, Box<dyn Error>>;
    /// # decode
    /// Should take a reference to a String and return T
    fn decode(s: &String) -> Result<Box<Self>, Box<dyn Error>>;
    /// # send_raw
    /// Encodes T into a string and sends it to the peer
    /// # Params
    /// Takes a reference to self, a mutable refrence to a TcpStream and a bool value. The bool value the function if it should flush the stream after use.
    /// If you want your data to get there promptly and it is small you should use this. In low profile you should not
    ///
    /// # Panics
    /// Does not panic but can return a Error
    ///
    /// # Blocking
    /// This function will not block and makes no assumptions about the state of the peer;
    /// Just because this returns Ok(()) does not mean the peer is connected or has seen the message
    fn send_raw(&self, peer: &mut TcpStream, _flush: bool) -> Result<(), Box<dyn Error>> {
        let en = self.encode()?;
        let buf = en.as_bytes();
        peer.write(&buf)?;
        if true {
            // TEMP FIX, always flush stream                  flush {
            peer.flush()?;
        }
        return Ok(());
    }
}
/// A struct to allow you to easly use strings with the Sendable trait
struct S {
    pub c: String,
}

impl Sendable for S {
    fn encode(&self) -> Result<String, Box<dyn Error>> {
        return Ok(self.c.clone());
    }
    fn decode(s: &String) -> Result<Box<Self>, Box<dyn Error>> {
        return Ok(S { c: s.clone() }.into());
    }
}

impl S {
    pub fn from_string(s: String) -> Self {
        S { c: s }
    }
    pub fn to_string(self) -> String {
        self.c
    }
}

/// # Send
/// This function will form a P2pData Struct from your message and message type, encode it into a string and send it to the specifyed stream
/// It is a convienience wrapper wrong the sen function from the Sendable trait
/// # Params
/// Takes a mutable refrence to a TcpStream, a bool value and a Option<slice>. The bool value the function if it should flush the stream after use.
/// If you want your data to get there promptly and it is small you should use this. In low profile you should not.
/// The option<slice> is the key, if not passed it will attempt to get it from the PEERS global variable. If that fails it will return an Error
///
///  # Panics
/// Does not panic but can return a Error
///
/// # Blocking
/// This function will not block and makes no assumptions about the sate of the peer;
/// Just because this returns Ok(()) does not mean the peer is connected or has seen the message
pub fn send(
    msg: String,
    peer: &mut TcpStream,
    msg_type: u16,
    flush: bool,
    key: Option<&[u8; 32]>,
) -> Result<(), Box<dyn Error>> {
    //let p2p_dat = P2pData::gen(msg, msg_type);
    //p2p_dat.log();
    let data: String = msg;
    let s: S;
    let mut k: AesGcm;
    if key.is_some() {
        // did the function get called with a custom key?
        let mut key_unwraped = &[0u8; 32];
        key_unwraped = key.unwrap();
        trace!("KEY: {:?}, LEN: {}", key_unwraped, key_unwraped.len());
        let mut k = AesGcm::new(
            // create a new decoder (AesGcm) object using passed key
            KeySize::KeySize128,
            key_unwraped,
            &[0; 12],
            &[0; 1], //p2p_dat.length().to_string().as_bytes(),
        );
        // vectors for AES GCM components
        let mut tag = vec![0; 16];
        let mut output = vec![0; data.as_bytes().len()];
        let _ = k.encrypt(data.as_bytes(), &mut output, &mut tag); // encrypt the data
        let p2p_dat = P2pData::gen(
            format!("{}@{}", hex::encode(output), hex::encode(tag)),
            msg_type,
        );
        p2p_dat.log();
        s = S {
            // turn encrypted data into a wrapper object (for sendable trait)
            c: p2p_dat.to_string(),
        };
    } else {
        // use key in PEERS lazy staitic
        let map = PEERS.lock()?; // gets a mutex "lock" on the PEERS lazy static. Prevents data races accross diffrent threads. Can lock up.
        if let Some(val) = map.get(&strip_port(&peer.peer_addr()?)) {
            trace!(
                "Sending message, key: {:?}, LEN: {}",
                hex::decode(&val.0),
                hex::decode(&val.0).unwrap_or_default().len()
            );
            let nonce = &[0; 12];
            trace!("NONCE: {:?}, LEN: {}", nonce, nonce.len());
            k = AesGcm::new(
                // create a new decoder (AesGcm) object using stored key
                KeySize::KeySize128,
                &hex::decode(&val.0).unwrap_or_default(), // keys are stored encoded as hex, not utf8 strings
                nonce,
                &[0; 1], //TODO: use adaptive nonce (eg p2p_dat.length().to_string().as_bytes())
            );
            // variables for encryption output
            let mut tag = vec![0; 16];
            let mut output = vec![0; data.as_bytes().len()];
            let _ = k.encrypt(data.as_bytes(), &mut output, &mut tag);
            let p2p_dat = P2pData::gen(
                format!("{}@{}", hex::encode(output), hex::encode(tag)), // create the P2P data struct with the encrypted data
                msg_type,
            );
            p2p_dat.log();
            s = S {
                c: p2p_dat.to_string(),
            };
        } else {
            return Err("No key provided and peer not found".into());
        }
    }
    trace!("s={}", s.c);
    return s.send_raw(peer, flush); // send the string form of the formed P2P data struct.
}

/// # Read
/// Reads data from the specifyed stream and parses it into a P2pData struct.
///
/// # Params
/// Takes a mutable refrence to a TcpStream, a Option<u64> value and a Option<slice> value. The Option value is the timeout.
/// If set it tells the function long to wait before returning if we dont get any data. If set to None it will block
/// infinitly or untll data is got. The Option<Slice> value is they encryption key. If None it will get from the PEERS global value
///
/// # Panics
/// Does not panic but can return a Error
///
/// # Blocking
/// This function will block until either:
/// * The time since start exceeds the timeout value (if it is set)
/// * It reads the data
pub fn read(
    peer: &mut TcpStream,
    timeout: Option<u64>,
    key: Option<&[u8]>,
) -> Result<P2pData, Box<dyn Error>> {
    let start = std::time::SystemTime::now();
    loop {
        if timeout.is_some() {
            if std::time::SystemTime::now()
                .duration_since(start)?
                .as_millis() as u64 // get time, im MS, since the calling of the function. If it is over timeout, return Err
                > timeout.unwrap()
            {
                return Err("Timed out".into());
            }
        }
        let mut lenbuf = [0u8; LEN_DECL_BYTES]; // create a buffer to store the LEN BYTES tag which is preappended to every message (which tells us the size of the incoming message)
        if let Ok(a) = peer.peek(&mut lenbuf) {
            // peek to see if there is LEN_DECL_BYTES or more of data ready for us
            if a == 0 {
            } else {
                trace!("a={}", a);
                // read exactly LEN_DECL_BYTES into buf
                peer.read_exact(&mut lenbuf)?;
                // convert the LEN_DECL_BYTES bytes into a string
                trace!("Read exactly {} bytes into LEN BYTES buffer", a);
                let len_s = String::from_utf8(lenbuf.to_vec())?; // turn read bytes into a UTF-8 string
                let len_striped: String = len_s.trim_start_matches("0").to_string(); // trims 0 which pad the LEN BYTES number to make it always LEN_DECL_BYTES long
                let len: usize = len_striped.parse()?; // turn string (eg 129) into a usize (unsized int)
                trace!("LEN_S={}", len_s);
                let mut k: AesGcm;
                if key.is_some() {
                    // if we were passed a custom key use that
                    k = AesGcm::new(
                        // create a decoder object from cusstom passed key
                        KeySize::KeySize128,
                        key.unwrap(), // Key must be 16 or 32 bytes
                        &[0; 12],     // nonce must be 96 bits, or 12 bytes
                        &[0; 1],      // AAD
                    );
                } else {
                    // if not get it from the PEERS lazy static
                    debug!("Awaiting lock on PEERS mutex");
                    let map = PEERS.lock()?; // get a mutex lock on PEERS lazy static
                    debug!("Gained lock on PEERS mutex");
                    if let Some(val) = map.get(&strip_port(&peer.peer_addr()?)) {
                        // get the peer's wrapper object from the PEERS lazy static
                        k = AesGcm::new(
                            // create a decoder object from the stored key
                            KeySize::KeySize128,
                            &hex::decode(&val.0).unwrap_or_default(), // Key must be 16 or 32 bytes
                            &[0; 12], // nonce must be 96 bits, or 12 bytes
                            &[0; 1],  // AAD
                        );
                    } else {
                        return Err("No key provided and peer not found".into());
                        // peer was not found in lazy static and no custom key was passed; return Err
                    }
                }
                let mut buf = vec![0u8; len]; // create a new buffer with the number of bytes specified by LEN BYTES tag
                trace!("Reading {} bytes into main buffer", len);
                peer.read_exact(&mut buf)?; // read exactly LEN BYTES tag into buf, this is our main message
                trace!(
                    "Read {} bytes into BUF={:?} ({})",
                    len,
                    buf,
                    buf.len() == len
                );
                let mut s: String = String::from_utf8(buf.to_vec())? // turn buf into string
                    .trim_matches('0') // trim 'floating' 0s caused by noisy read
                    .to_string(); // turn outputed &str into String (realloactes, expensive)
                let removed_braces = s[..len - 14].to_owned(); // remove everything outside the braces
                let as_s = "{".to_string() + &removed_braces + "}"; // reads braces (to reform the json string)
                trace!("S={}, AS_S={}, REMOVED_BRACES={}", s, as_s, removed_braces,);
                let p2p_dat: P2pData = match serde_json::from_str(&removed_braces) {
                    // use serde to turn the json string into a P2P data struct
                    Ok(s) => s,
                    Err(e) => {
                        debug!("Failed to decode P2pData from json, gave error: {}", e);
                        P2pData::default()
                    }
                };
                p2p_dat.log();
                s = p2p_dat.message.clone(); // the message being sent, can be block data, peerlist etc depnsing on the p2p_dat.type
                let s_split: Vec<&str> = s.split("@").collect(); // split the AES_GCM encoded string by the delimmiter token ("@")
                if s_split.len() < 1 {
                    // there should be 2 values: tag and message (eg len > 1)
                    return Err("No auth tag".into());
                } else {
                    trace!("s_spilt={:?}, LEN={}", s_split, s_split.len());
                    let cf: &[u8] = &hex::decode(s_split[0])?; // turn the message segment into a vector of bytes
                    let tag: &[u8] = &hex::decode(s_split[1])?; // turn the tag segment into a vector of bytes
                    let mut out = vec![0u8; cf.len()]; // the output length will always == encrypted message (cf).len(); preallocate vector to store this
                    if !k.decrypt(cf, &mut out, tag) {
                        // try to decrypt the message using previously created decoder object
                        return Err("failed to decrypt message".into());
                    } else {
                        trace!("OUT={}", String::from_utf8(out.clone())?);
                        return Ok(P2pData::new(
                            // create a p2p object containing: out - teh decoded message, the message type, the checksum, then len and return it
                            len,
                            String::from_utf8(out)?,
                            p2p_dat.message_type,
                            p2p_dat.checksum(),
                        ));
                    }
                }
            }
        }
    }
}
