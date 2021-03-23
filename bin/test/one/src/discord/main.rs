

use serenity::{
    async_trait,
    model::{
        channel::Message,
        gateway::{Activity, Ready},
        id::{ChannelId, GuildId},
    },
    prelude::*,
};

struct Handler;
static txn_notif_channel_id: u64 = 823568815350480916;
static mut ctx_holder: Option<Context> = None;
#[async_trait]
impl EventHandler for Handler {
    async fn message(&self, _ctx: Context, msg: Message) {
        if msg.content == "!test" {
            println!("test txn command");
            // Sending a message can fail, due to a network error, an
            // authentication error, or lack of permissions to post in the
            // channel, so log to stdout when some error happens, with a
            // description of it.
            let mut txn = avrio_core::transaction::Transaction::default();
            txn.amount = 10;
            txn.sender_key = "0xuwhiu3iy78ufihyhijdu".to_string();
            txn.receive_key = "0xiu38uidojekuy89iedo".to_string();
            txn.hash();
            recieved_txn(txn).await;
        }
    }

    async fn ready(&self, ctx: Context, ready: Ready) {
        println!("{} is connected!", ready.user.name);
        unsafe { ctx_holder = Some(ctx) }
    }
}

pub async fn recieved_txn(txn: avrio_core::transaction::Transaction) {
    println!("Discord hook: {:?}", txn);
    unsafe {
        if let Err(why) = ChannelId(txn_notif_channel_id)
            .send_message(&ctx_holder.clone().unwrap(), |m| {
                m.embed(|e| {
                    e.title("New Txn recieved");
                    e.field("Hash", format!("{}", txn.hash), false);
                    e.field("Amount transfered", format!("{} ", txn.amount), false);
                    e.field("Sender", format!("{} ", txn.sender_key), false);
                    e.field("Reciever", format!("{} ", txn.receive_key), false);
                    // e.field("Timestamp", format!("{} ", txn.timestamp), false);
                    //e.field("Signature", format!("{} ", txn.signature), false);
                    //e.field("Gas, gas price, total fee", format!("{}, {}, {} ", txn.gas, txn.gas_price, txn.gas * txn.gas_price), false);
                    e.footer(|f| {
                        f.text("Avro Testnet Bot");

                        f
                    });
                    e
                });
                m
            })
            .await
        {
            println!("Error sending message: {:?}", why);
        };
    }
}

#[tokio::main]
async fn main() {
    // Configure the client with your Discord bot token in the environment.
    let token = avrio_config::config().discord_token;
    let mut client = Client::builder(&token)
        .event_handler(Handler)
        .await
        .expect("Err creating client");

    if let Err(why) = client.start().await {
        println!("Client error: {:?}", why);
    }
}
