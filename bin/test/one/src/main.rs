// Testnet one,
// This testnet foucouses on the P2p code, on launch a node will conect to the seed node(/s),
// get the peer list and connect to the other nodes on this peerlist. Then every 5 mins they 
//generate a block and release it (to test the p2p propigation code). 

pub extern crate config;
pub extern crate core;
pub extern crate crypto;
pub extern crate p2p;
pub extern crate blockchain;
pub extern crate database;

fn main() {
    let art: String = "
   #    #     # ######  ### ####### 
  # #   #     # #     #  #  #     # 
 #   #  #     # #     #  #  #     # 
#     # #     # ######   #  #     # 
#######  #   #  #   #    #  #     # 
#     #   # #   #    #   #  #     # 
#     #    #    #     # ### ####### ";
    print!("{}", art);
    println!("Avrio Daemon Testnet v1.0.0 (pre-alpha)");
    println!("[INFO] Checking for previous startup");
    let startup_state: u16 = match database::new_startup() {
        true => existingStartup(),
        false => noExistingStartup(),
    };
    if startup_state == 1 { // succsess
        println!("[INFO] Avrio Daemon succsessfully launched");
        match p2p::sync_needed() { // do we need to sync
            true => sync();
            false => fullySynced();
        }
    }
    if synced() == true 
    {
        if p2p::message_buffer.len() != 0 {
            handle_new_messages(message_buffer);
        } else {
        // create block
            let new_block == Block 
            {
                header: Header {
                    version_major: 0,
                    version_minor: 0
                    chain_key: chainKey,
                    prev_hash: hex::encode(get_last_blockhash(chainKey),
                    height: 0,
                    timestamp: 0,
                },
                txns: blank_txn,
            }
            new_block.hash = new_block.hash();
            new_block.signature = new_block.sign(private_key, new_block.hash);
            let mut new_block_s: String;
            if blockchain::check_block(new_block) {
                new_block_s = serde_json::to_string(&new_block).unwrap();
                new_block_s = hex::encode(new_block_s);
                let state = p2p::send_to_all(&new_block_s);
                if state != Err(p2pError::none) { // there was an error
                    println("[ERROR] Failed to propiagte block {:?}, encountered error: {:?}", new_block_s, state); // tell them the error
                    println!("[ERROR] Block dump: non serilised {:?}, hex encoded serilised {:?}, hex decoded serilised {:?}", new_block, new_block_s, hex::decode(new_block_s)); // now flood their eyes with hex 
                }
            }
        }
   }  
}
