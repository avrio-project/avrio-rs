use crate::format::{P2pData, LEN_DECL_BYTES};
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;

pub trait Sendable {
    /// # Encode 
    /// Should encode T into a String that can be transported and then decoded with the decode function
    fn encode(&self) -> Result<String, Box<dyn Error>>;
    /// # Decode
    /// Should take a reference to a String and return T
    fn decode(s: &String) -> Result<Box<Self>, Box<dyn Error>>;
    /// # Send
    /// Encodes T into a string and sends it to the peer
    /// # Params
    /// Takes a reference to self, a mutable refrence to a TcpStream and a bool value. The bool value the function if it should flush the stream after use.
    /// If you want your data to get there promptly and it is small you should use this. In low profile you should not
    ///
    /// # Panics
    /// Does not panic but can return a Error
    ///
    /// # Blocking
    /// This function will not block and makes no assumptions about the sate of the peer;
    /// Just because this returns Ok(()) does not mean the peer is connected or has seen the message
    fn send(&self, peer: &mut TcpStream, flush: bool) -> Result<(), Box<dyn Error>> {
        let en = self.encode()?;
        let buf = en.as_bytes();
        peer.write(&buf)?;
        if flush {
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
/// Takes a mutable refrence to a TcpStream and a bool value. The bool value the function if it should flush the stream after use.
/// If you want your data to get there promptly and it is small you should use this. In low profile you should not
///
/// # Panics
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
) -> Result<(), Box<dyn Error>> {
    let s: S = S::from_string(P2pData::gen(msg, msg_type).to_string());
    return s.send(peer, flush);
}

/// # Read
/// Reads data from the specifyed stream and parses it into a P2pData struct.
///
/// # Params
/// Takes a mutable refrence to a TcpStream and a Option<u64> value. The Option value is the timeout.
/// If set it tells the function long to wait before returning if we dont get any data. If set to None it will block
/// infinitly or untll data is got.
///
/// # Panics
/// Does not panic but can return a Error
///
/// # Blocking
/// This function will block until either:
/// * The time since start exceeds the timeout value (if it is set)
/// * It reads the data
pub fn read(peer: &mut TcpStream, timeout: Option<u64>) -> Result<P2pData, Box<dyn Error>> {
    let start = std::time::SystemTime::now();
    loop {
        if timeout.is_some() {
            if std::time::SystemTime::now()
                .duration_since(start)?
                .as_millis() as u64
                > timeout.unwrap()
            {
                return Err("Timed out".into());
            }
        }
        let mut buf = [0; LEN_DECL_BYTES];
        if let Ok(a) = peer.peek(&mut buf) {
            if a < 0 {
            } else {
                peer.read_exact(&mut buf)?;
                let len_s = String::from_utf8(buf.to_vec())?;
                let len_striped: String = len_s.trim_start_matches("0").to_string();
                let len: usize = len_striped.parse()?;
                let mut buf = Vec::with_capacity(len);
                peer.read_exact(&mut buf)?;
                let s: String = String::from_utf8(buf.to_vec())?
                    .trim_matches('0')
                    .to_string();
                return Ok(P2pData::from_string(&format!("{}{}{}", len_s, s, len_s)));
            }
        }
    }
}
