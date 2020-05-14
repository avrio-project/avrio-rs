use lazy_static::lazy_static;
use std::collections::HashMap;
lazy_static! {
    static ref MSG_TYPES: HashMap<u16, &'static str> = get_message_types();
}

fn get_message_types() -> HashMap<u16, &'static str> {
    let mut message_types = HashMap::new();

    message_types.insert(0, "Raw / Invalid");
    message_types.insert(0x22, "Sync Request");
    message_types.insert(0x23, "Sync Close");
    message_types.insert(0x01, "Sync Acknowledged");
    message_types.insert(0x05, "Send Block");
    message_types.insert(0x0a, "Block");
    message_types.insert(0x0b, "Block Acknowledged");
    message_types.insert(0x0c, "Block Reject");
    // 4 part handshake
    message_types.insert(0x0a, "Handshake Init");
    message_types.insert(0xa1, "Handshake Init Response");
    message_types.insert(0xa2, "Handshake Test Key");
    message_types.insert(0xa3, "Handshake Confirm Key Test");

    // chain digests
    message_types.insert(0x1b, "Send Chain Digest (ask)");
    message_types.insert(0x1c, "Send Chain Digest (ask)");
    message_types.insert(0xcd, "Send Chain Digest (response)");
    message_types.insert(0x45, "Send Block Count");
    message_types.insert(0x46, "Got Block Count");
    message_types.insert(0x60, "Get Chain List");
    message_types.insert(0x61, "Got Chain List");
    message_types.insert(0x6f, "Get Block Above Hash");
    message_types.insert(0x99, "Get Peer List");
    message_types.insert(0x9f, "Got Peer List");
    message_types.insert(0xff, "Shutdown");

    return message_types;
}

pub fn get_message_type(message_type: &u16) -> &str {
    let message_types = &MSG_TYPES;
    let message_type_option = message_types.get(message_type);

    match message_type_option {
        None => return "Unknown",
        Some(m) => return m,
    }
}
