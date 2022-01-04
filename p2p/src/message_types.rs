use lazy_static::lazy_static;
use std::collections::HashMap;
lazy_static! {
    static ref MSG_TYPES: HashMap<u16, &'static str> = get_message_types();
}

fn get_message_types() -> HashMap<u16, &'static str> {
    let mut message_types = HashMap::new();

    message_types.insert(0, "Raw / Invalid");
    message_types.insert(0x03, "Rehandshake");
    message_types.insert(0x04, "Block");
    message_types.insert(0x05, "Send Block");
    message_types.insert(0x06, "Generate epoch salt (ask)"); // used by consensus commitee round leader
    message_types.insert(0x07, "Generate epoch salt (response)"); // sent back to consensus commitee round leader
    message_types.insert(0x8f, "Send peerlist (ask)");
    message_types.insert(0x9f, "Send peerlist (response)");
    message_types.insert(0x22, "Sync Request");
    message_types.insert(0x23, "Sync Close");
    message_types.insert(0x01, "Sync Acknowledged");
    message_types.insert(0x0a, "Handshake Init");
    message_types.insert(0x0b, "Block Acknowledged");
    message_types.insert(0x0c, "Block Reject");
    message_types.insert(0xa1, "Handshake Init Response");
    message_types.insert(0xa2, "Handshake Test Key");
    message_types.insert(0xa3, "Handshake Confirm Key Test");
    message_types.insert(0xa4, "Get prechunk block hashes");
    message_types.insert(0xa5, "Prechunk block hashes");
    message_types.insert(0x1b, "Send Chain Digest (ask)"); // - why are there two? Backward combatability?
    message_types.insert(0x1c, "Send Chain Digest (ask)"); // TODO: remove one
    message_types.insert(0xcd, "Send Chain Digest (response)");
    message_types.insert(0x45, "Get Block Count (ask)");
    message_types.insert(0x46, "Get Block Count (response)");
    message_types.insert(0x47, "Get Global Block Count (ask)");
    message_types.insert(0x48, "Get Global Block Count (response)");
    message_types.insert(0x49, "Get block chunk (ask)");
    message_types.insert(0x50, "Block chunk (response)");
    message_types.insert(0x51, "Get block chunk range (ask)");
    message_types.insert(0x52, "Get block chunk range (response)");
    message_types.insert(0x53, "Block chunk signature");
    message_types.insert(0x54, "Block chunk ack (no sig)");
    message_types.insert(0x55, "Block chunk proposal invalid");
    message_types.insert(0x60, "Get Chain List (ask)");
    message_types.insert(0x61, "Get Chain List (response)");
    message_types.insert(0x62, "Generate epoch salt seeds (ask)");
    message_types.insert(0x63, "Generate epoch salt seeds (response)");
    message_types.insert(0x64, "Propose chunk for round");
    message_types.insert(0x6f, "Get Block Above Hash, chain concurrent"); // get the blocks above hash x, concurernt to chain c
    message_types.insert(0x7f, "Get Block Above Hash, global concurrent"); // get the blocks above hash x, but globally concurernt rather than chain concurrent
    message_types.insert(0x91, "Ping");
    message_types.insert(0x92, "Pong");
    message_types.insert(0x99, "Get Peer List (ask)");
    message_types.insert(0x9f, "Get Peer List (response)");
    message_types.insert(0x9a, "Announce peer");
    message_types.insert(0xff, "Shutdown");
    message_types
}

pub fn get_message_type(message_type: &u16) -> &str {
    let message_types = &MSG_TYPES;
    let message_type_option = message_types.get(message_type);

    message_type_option.unwrap_or(&"Unknown")
}
