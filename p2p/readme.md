# Avrio P2p
This crate contains the versatile and strongly typed custom p2p system writen by Leo Cornelius for avrio. It uses a 9 bit length decleration tag before messages and message encoding cna be easily changed. A single byte (u8) type declaration is used.

## Encryption
Message are encryped using AES GCM which proves both message integrity as well as keeping contense secret. This allows sensitive data like epoch salt seeds to be sent without the risk of MITM attacks intercepting this data and leaking or modifiying it. 

## Handshake
There is a 4 part handshake message based on the ECDHE scheme. This sets up the encryption keys for the connection which are saved with a certain expirey period (TODO: SAVING KEYS). Any futher connections (within this expirary period) will be only 2 part as they will resuse this key. After this epirey period the keys will be re calulcated for security

## Server - Client model
All nodes run both a recieving server that handles incoming connections as well as a outgoing server system. Each connection has its own thread that handles incoming connetions. The handling of messages as well as the code for this handling server can be found in handle.rs

## Message encoding
``LEN_TAG: 9 bits + MESSAGE: LEN_TAG bits + CHECKSUM: 5 bits + LEN_TAG: 9 bits``
Messages have a 9 bit length tag appened to them at the start and end. THe json encoded message then follows, followed by a 5 byte checksum (the first 5 bytes of a hash of the message) and the same 9 bit length tag. The code for this can be found in format.rs. 
