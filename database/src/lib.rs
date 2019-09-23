use serde::{Serialize, Deserialize};
use rocksdb::{DB, Options};
use account::Account;
use config::config;

fn opendb(path: String) -> rocksdb::DB {
    let db = DB::open_default(path).unwrap();
    return db;
}

fn setAccount(acc: Account) -> u8 {
    let path = config.path +"/db/accountdb"
    let db = DB::open_default(path).unwrap();
    let serialized = serde_json::to_string(&acc).unwrap();
    db.put(acc.public_key, serialized);
    return 1;
}

fn getAccount(public_key: String) -> Account{
    let path = config.path + "/bd/accountdb";
    let db = DB::open_default(path).unwrap();
    let accS;
    let state = 1;
    match db.get(public_key) {
        Ok(Some(value)) => accS = value.to_utf8().unwrap()),
        Ok(None) => state = 2,
        Err(e) => state = 0,
    }
    let nullAcc = Account;
    if state != 1 {
        return nullAcc;
    } else {
        var acc = serde_json::from_str(&accS).unwrap();
    }
    return acc;
}

