use fern::colors::{Color, ColoredLevelConfig};
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Debug)]
pub struct Blockcount {
    pub success: bool,
    pub blockcount: u64,
}
#[derive(Clone, Deserialize, Debug)]
pub struct Transactioncount {
    pub success: bool,
    pub transaction_count: u64,
}

#[derive(Clone, Deserialize, Debug)]
pub struct HashAtHeight {
    pub success: bool,
    pub hash: String,
}

#[derive(Clone, Deserialize, Debug)]
pub struct PublickeyForUsername {
    pub success: bool,
    pub publickey: String,
}

#[derive(Clone, Deserialize, Debug)]
pub struct Balances {
    pub success: bool,
    pub chainkey: String,
    pub balance: u64,
    pub locked: u64,
}

pub fn setup_logging(verbosity: u64) -> Result<(), fern::InitError> {
    let mut base_config = fern::Dispatch::new();
    base_config = match verbosity {
        0 => {
            // Let's say we depend on something which whose "info" level messages are too
            // verbose to include in end-user output. If we don't need them,
            // let's not include them.
            base_config
                .level(log::LevelFilter::Error)
                .level_for("avrio_database", log::LevelFilter::Error)
                .level_for("avrio_config", log::LevelFilter::Error)
                .level_for("avrio_wallet", log::LevelFilter::Error)
                .level_for("avrio_core", log::LevelFilter::Error)
                .level_for("avrio_crypto", log::LevelFilter::Error)
                .level_for("avrio_rpc", log::LevelFilter::Error)
                .level_for("avrio_p2p", log::LevelFilter::Error)
                .level_for("avrio_wallet_service", log::LevelFilter::Error)
        }
        1 => base_config
            .level(log::LevelFilter::Warn)
            .level(log::LevelFilter::Error)
            .level_for("avrio_database", log::LevelFilter::Warn)
            .level_for("avrio_config", log::LevelFilter::Warn)
            .level_for("seednode", log::LevelFilter::Warn)
            .level_for("avrio_core", log::LevelFilter::Warn)
            .level_for("avrio_crypto", log::LevelFilter::Warn)
            .level_for("avrio_wallet", log::LevelFilter::Warn)
            .level_for("avrio_p2p", log::LevelFilter::Warn)
            .level_for("avrio_rpc", log::LevelFilter::Warn)
            .level_for("avrio_wallet_service", log::LevelFilter::Warn),

        2 => base_config
            .level(log::LevelFilter::Warn)
            .level_for("avrio_database", log::LevelFilter::Info)
            .level_for("avrio_config", log::LevelFilter::Info)
            .level_for("seednode", log::LevelFilter::Info)
            .level_for("avrio_core", log::LevelFilter::Info)
            .level_for("avrio_crypto", log::LevelFilter::Info)
            .level_for("avrio_p2p", log::LevelFilter::Info)
            .level_for("avrio_wallet", log::LevelFilter::Info)
            .level_for("avrio_rpc", log::LevelFilter::Info)
            .level_for("avrio_wallet_service", log::LevelFilter::Info),
        3 => base_config
            .level(log::LevelFilter::Warn)
            .level_for("avrio_database", log::LevelFilter::Debug)
            .level_for("avrio_config", log::LevelFilter::Debug)
            .level_for("seednode", log::LevelFilter::Debug)
            .level_for("avrio_core", log::LevelFilter::Debug)
            .level_for("avrio_crypto", log::LevelFilter::Debug)
            .level_for("avrio_p2p", log::LevelFilter::Debug)
            .level_for("avrio_wallet", log::LevelFilter::Debug)
            .level_for("avrio_rpc", log::LevelFilter::Debug)
            .level_for("avrio_wallet_service", log::LevelFilter::Debug),
        _ => base_config
            .level(log::LevelFilter::Warn)
            .level_for("avrio_database", log::LevelFilter::Trace)
            .level_for("avrio_config", log::LevelFilter::Trace)
            .level_for("seednode", log::LevelFilter::Trace)
            .level_for("avrio_core", log::LevelFilter::Trace)
            .level_for("avrio_wallet", log::LevelFilter::Trace)
            .level_for("avrio_p2p", log::LevelFilter::Trace)
            .level_for("avrio_crypto", log::LevelFilter::Trace)
            .level_for("avrio_rpc", log::LevelFilter::Trace)
            .level_for("avrio_wallet_service", log::LevelFilter::Trace),
    };

    // Separate file config so we can include year, month and day in file logs
    let file_config = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .chain(fern::log_file("avrio-wallet.log")?);

    let stdout_config = fern::Dispatch::new()
        .format(|out, message, record| {
            let colors = ColoredLevelConfig::default()
                .info(Color::Green)
                .debug(Color::Magenta);
            // special format for debug messages coming from our own crate.
            if record.level() > log::LevelFilter::Info && record.target() == "cmd_program" {
                out.finish(format_args!(
                    "---\nDEBUG: {}: {}\n---",
                    chrono::Local::now().format("%H:%M:%S"),
                    message
                ))
            } else {
                out.finish(format_args!(
                    "{}[{}][{}] {}",
                    chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                    record.target(),
                    colors.color(record.level()),
                    message
                ))
            }
        })
        .chain(std::io::stdout());

    base_config
        .chain(file_config)
        .chain(stdout_config)
        .apply()?;
    Ok(())
}
