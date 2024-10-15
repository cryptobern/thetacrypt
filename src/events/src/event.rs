use core::fmt;

use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub enum Event {
    // // Emitted when the server received a decryption request.
    // ReceivedDecryptionRequest {
    //     timestamp: DateTime<Utc>,
    // },
    // Emitted when an instance of the decryption protocol started.
    StartedInstance {
        timestamp: DateTime<Utc>,
        instance_id: String,
    },
    // Emitted when an instance of the decryption protocol terminated.
    FinishedInstance {
        timestamp: DateTime<Utc>,
        instance_id: String,
    },

    // Emitted when an instance terminates with an error.
    FailedInstance {
        timestamp: DateTime<Utc>,
        instance_id: String,
        // maybe include an error code here?
        error_message: String,
    },

    // // Emitted when the server received a signing request.
    // ReceivedSigningRequest {
    //     timestamp: DateTime<Utc>,
    // },
    // // Emitted when an instance of the signing protocol started.
    // StartedSigningInstance {
    //     timestamp: DateTime<Utc>,
    //     instance_id: String,
    // },
    // // Emitted when an instance of the signing protocol terminated.
    // FinishedSigningInstance {
    //     timestamp: DateTime<Utc>,
    //     instance_id: String,
    // },

    // // Emitted when the server received a coin request.
    // ReceivedCoinRequest {
    //     timestamp: DateTime<Utc>,
    // },
    // // Emitted when an instance of the coin protocol started.
    // StartedCoinInstance {
    //     timestamp: DateTime<Utc>,
    //     instance_id: String,
    // },
    // // Emitted when an instance of the coin protocol terminated.
    // FinishedCoinInstance {
    //     timestamp: DateTime<Utc>,
    //     instance_id: String,
    // },
}

#[derive(Debug)]
pub enum BenchmarkingError {
    InternalError(String),
    IOError(std::io::Error),
}

impl fmt::Display for BenchmarkingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BenchmarkingError::InternalError(s) => write!(f, "Internal error: {}", s),
            BenchmarkingError::IOError(err) => write!(f, "IO error: {}", err),
        }
    }
}

pub mod emitter {
    use std::{fs::File, io::Write, path::PathBuf, sync::Arc};

    use log::{debug, error, info, warn};
    use tokio::{
        sync::{
            mpsc::{self, Receiver, Sender},
            oneshot, Notify,
        },
        task::JoinHandle,
    };

    use super::{BenchmarkingError, Event};

    /// Start an emitter in a Tokio thread. Returns the channel through which the emitter can be fed
    /// events, a channel through which the emitter can be shut down, as well as the emitter's thread handle.
    pub fn start(
        emitter: Emitter,
        shutdown_notify: Arc<Notify>
    ) ->
        Result<
        (Sender<Event>,
        JoinHandle<Result<(), String>>),
        BenchmarkingError >
     {
         // We re-open the file such that we can move the file handle into the thread.
        let fh = File::options()
        .create(true)
        .append(true)
        .open(&emitter.outfile)
        .map_err(|e| BenchmarkingError::IOError(e))?;

        let (tx, rx) = mpsc::channel::<Event>(100);
        let handle = tokio::spawn(async move { 
            //Handel the error in case of failure to start the emitter
            emitter.run(fh, rx, shutdown_notify).await 
        });

        Ok((tx, handle))
    }

    /// Starts a null emitter which behaves like a regular emitter, but discards all events
    /// passed to it.
    pub fn start_null_emitter(shutdown_notify: Arc<Notify>) -> (
        Sender<Event>,
        JoinHandle<Result<(), String>>,
    ) {
        let (tx, mut rx) = mpsc::channel::<Event>(100);
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ =  shutdown_notify.notified() => {
                        warn!("Null-emitter shutting down. Nothing was achieved :)");
                        return Ok(())
                    }, // Terminate on shutdown signal
                    Some(_) = rx.recv() => {}, // Discard incoming events
                }
            }
        });

        (tx, handle)
    }

    /// New initializes a new emitter.
    pub fn new(outfile: &PathBuf) -> Emitter {
        Emitter {
            outfile: outfile.clone(),
        }
    }

    pub struct Emitter {
        outfile: PathBuf,
    }

    impl Emitter {
        /// Start listening for events on the given channel, and write them to the output file. The
        /// emitter will keep running until a value is received via the shutdown channel.
        pub async fn run(
            &self,
            mut file: File,
            mut rx: Receiver<Event>,
            shutdown_notify: Arc<Notify>,
        ) -> Result<(), String> {

            info!("Ready and waiting for events");
            loop {
                tokio::select! {
                    event = rx.recv() => {
                        match event {
                            Some(event) => {
                                debug!("Emitting event: {:?}", event);
                                // We'll unwrap here, to noisly faily should serialization fail
                                let data = serde_json::to_string(&event).unwrap();
                                writeln!(file, "{}", data).unwrap();
                            },
                            None => {
                                warn!("Emitter channel closed. Terminating.");
                                return Err("Emitter channel closed.".to_string());
                            }
                        }
                    },
                    _ = shutdown_notify.notified() => {            
                        info!("Event listener received shutdown command. Terminating.");
                        return Ok(());
                    },
                }
            }
        }
    }
}
