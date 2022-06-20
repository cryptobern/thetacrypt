use futures::future; // 0.3.19
use std::time::Duration;
use tokio::{
    sync::mpsc::{self, UnboundedSender},
    time,
}; // 1.16.1

async fn message_sender(msg: &'static str, tx: UnboundedSender<String>) {
    for count in 0.. {
        let message = format!("{msg}{count}");
        tx.send(message).unwrap();

        time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::main]
async fn main() {
    let (tx, mut rx) = mpsc::unbounded_channel();

    let sender_handle = tokio::spawn(message_sender("foo", tx));

    let receive_handle = tokio::spawn(async move {
        // let mut foo = None;

        loop {
            tokio::select! {
                msg = rx.recv() => {
                    if let Some(msg) = &msg {
                        println!("{msg}");
                    }
                }
            }
        }
    });

    future::join_all([sender_handle, receive_handle]).await;
}