use libp2p::*; // evil but easy 
pub enum p2p_errors {
  None,
  TimeOut,
  InvalidMultiAdrr,
  Other
}
function connect(peer: &Multiaddr) {
  let tcp = TcpConfig::new();
  let _conn = tcp.dial(peer.parse().expect("invalid multiaddr"););
  let mut error: p2p_errors = p2p_errors::None;
  return error;
}
