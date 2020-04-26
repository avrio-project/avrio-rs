use std::collections::HashMap;

pub fn get_message_types() -> HashMap<u16, &'static str> {
    let mut message_types = HashMap::new();

    message_types.insert(0, "Raw / Invalid");
    message_types.insert(0x01, "Sync Acknowledged");
    message_types.insert(0x05, "Send Block");
    message_types.insert(0x0a, "Get Block");
    message_types.insert(0x1a, "Handshake");
    message_types.insert(0x1b, "Send Chain Digest");
    message_types.insert(0x1c, "Send Chain Digest");
    message_types.insert(0x22, "Sync Request");
    message_types.insert(0x45, "Send Block Count");
    message_types.insert(0x60, "Get Chain List");
    message_types.insert(0x6f, "Get Block Above Hash");
    message_types.insert(0x99, "Get Peer List");
    message_types.insert(0xff, "Shutdown");

    return message_types;
}

pub fn get_message_type(message_type: &u16) -> &str {
    let message_types = get_message_types();

    let message_type_option = message_types.get(message_type);

    if message_type_option.is_none() {
        return "Unknown";
    } else {
        return message_type_option.unwrap();
    }
}
