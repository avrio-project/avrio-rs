// Copyright 2020 the avrio core devs
/*
 This is the first attempt at a CLI avrio wallet.
 It uses the json rpc v1 provided by the avrio dameon.
*/

use avrio_config::config;
use avrio_core::{account::*, transaction::Transaction};
use avrio_database::*;
use text_io::read;

fn get_choice() -> u8 {
    println!("[1] Open an existing wallet");
    println!("[2] Create a wallet");
    println!("[3] Import private keys");
    let ans: u8 = read!();
    return ans;
}
fn main() {
    let matches = App::new("Avrio Wallet")
        .version("Testnet Pre-alpha 0.0.1")
        .about("This is the offical CLI wallet for the avrio network.")
        .author("Leo Cornelius")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config-file")
                .value_name("FILE")
                .help(
                    "(DOESNT WORK YET!!) Sets a custom config file, if not set will use node.conf",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("loglev")
                .long("log-level")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity: 0: Error, 1: Warn, 2: Info, 3: debug"),
        )
        .get_matches();
    match matches.value_of("loglev").unwrap_or(&"2") {
        "0" => simple_logger::init_with_level(log::Level::Error).unwrap(),
        "1" => simple_logger::init_with_level(log::Level::Warn).unwrap(),
        "2" => simple_logger::init_with_level(log::Level::Info).unwrap(),
        "3" => simple_logger::init_with_level(log::Level::Debug).unwrap(),
        "4" => simple_logger::init_with_level(log::Level::Trace).unwrap(),
        _ => panic!("Unknown log-level: {} ", matches.occurrences_of("loglev")),
    }
    //println!("{}", matches.occurrences_of("loglev"));
    let art = "
   #    #     # ######  ### #######
  # #   #     # #     #  #  #     #
 #   #  #     # #     #  #  #     #
#     # #     # ######   #  #     #
#######  #   #  #   #    #  #     #
#     #   # #   #    #   #  #     #
#     #    #    #     # ### ####### ";
    println!("{}", art);
    info!("Avrio Wallet Testnet v1.0.0 (pre-alpha)");
    let config_ = config();
    let _ = config_.save();
    info!("Welcome to the avrio wallet, please choose an option");
    match get_choice() {
        1 => open_wallet(),
        2 => create_wallet(),
        3 => import_wallet(),
        _ => {
            error!("Please choose a number beetween 1 and 3!");
            match get_choice() {
                1 => open_wallet(),
                2 => create_wallet(),
                3 => import_wallet(),
                _ => {
                    error!("Please choose a number beetween 1 and 3!");
                    match get_choice() {
                        1 => open_wallet(),
                        2 => create_wallet(),
                        3 => import_wallet(),
                        _ => {
                            error!("3 failed attempts, exiting");
                        }
                    };
                }
            };
        }
    };
}

fn open_wallet() -> bool {
    info!("Please enter the name of the wallet you want to open");
    let file_name = read!();
    let file_path = config().db_path + &"/wallets/".to_owned() + file_name;
    info!("Please enter your wallet password (hit enter with no input to read value from config)");
    let mut password: String = read!();
    if password == "".to_owned() {
        password = config().wallet_password;
    }
    if password == Config::default().wallet_password {
        warn!("Your wallet password is set to default, please change this password with change_password once you are into your wallet");
    }
    let mut padded = password.as_bytes().to_vec();
    while padded.len() != 32 && padded.len() < 33 {
        padded.push(b"n"[0]);
    }
    let padded_string = String::from_utf8(padded).unwrap();
    let key = GenericArray::clone_from_slice(padded_string.as_bytes());
    let aead = Aes256Gcm::new(key);
    let mut padded = b"nonce".to_vec();
    while padded.len() != 12 {
        padded.push(b"n"[0]);
    }
    let padded_string = String::from_utf8(padded).unwrap();
    let nonce = GenericArray::from_slice(padded_string.as_bytes()); // 96-bits; unique per message
    let ciphertext = get_data(file_path, &"pubkey".to_owned());
    let pubkey = String::from_utf8(
        hex::decode(aead.decrypt(nonce, ciphertext.as_ref()).unwrap_or({
            error!("Failed to decrypt wallet, likley incorect password");
            vec![0]
        }))
        .expect("failed to parse hex"),
    )
    .expect("failed to parse hex utf8");
    // now priv key
    let key = GenericArray::clone_from_slice(b"wallet-password");
    let aead = Aes256Gcm::new(key);
    // TODO: use unique nonce
    let nonce = GenericArray::from_slice(b"unique nonce"); // 96-bits; unique per message
    let ciphertext = get_data(file_path, &"privkey".to_owned());
    let privkey = String::from_utf8(
        hex::decode(aead.decrypt(nonce, ciphertext.as_ref()).unwrap_or({
            error!("Failed to decrypt wallet, likley incorect password");
            vec![0]
        }))
        .expect("failed to parse hex"),
    )
    .expect("failed to parse hex utf8");
    info!("Sucessfully opened wallet with public key: {}", pubkey);
    info!("Syncing with daemon");
    return true;
}

fn create_wallet() -> bool {
    return true;
}

fn import_wallet() -> bool {
    return true;
}
