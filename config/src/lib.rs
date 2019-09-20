use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct Config {
    version_major: u32,
    version_minor: u32,
    coin_name: String,
    node_drop_off_threshold: u64, // percent of online nodes that can go offline before a rearrange
    decimal_places: u8,
    max_connections: u16,
    max_threads: u8,
    chain_key: String,
    state: u8,
    host: u64,
}   

pub fn config() -> Config {
  Config {
    version_major: 1,
    version_minor: 0,
    coin_name: "aviro",
    node_drop_off_threshhold: 40,
    decimal_places: 4
  };
}
