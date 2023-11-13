use core::fmt;

use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub enum Event {
    // Emitted when the server received a decryption request.
    ReceivedDecryptionRequest {
        timestamp: DateTime<Utc>,
    },
    // Emitted when an instance of the decryption protocol started.
    StartedDecryptionInstance {
        timestamp: DateTime<Utc>,
        instance_id: String,
    },
    // Emitted when an instance of the decryption protocol terminated.
    FinishedDecryptionInstance {
        timestamp: DateTime<Utc>,
        instance_id: String,
    },

    // Emitted when the server received a signing request.
    ReceivedSigningRequest {
        timestamp: DateTime<Utc>,
    },
    // Emitted when an instance of the signing protocol started.
    StartedSigningInstance {
        timestamp: DateTime<Utc>,
        instance_id: String,
    },
    // Emitted when an instance of the signing protocol terminated.
    FinishedSigningInstance {
        timestamp: DateTime<Utc>,
        instance_id: String,
    },

    // Emitted when the server received a coin request.
    ReceivedCoinRequest {
        timestamp: DateTime<Utc>,
    },
    // Emitted when an instance of the coin protocol started.
    StartedCoinInstance {
        timestamp: DateTime<Utc>,
        instance_id: String,
    },
    // Emitted when an instance of the coin protocol terminated.
    FinishedCoinInstance {
        timestamp: DateTime<Utc>,
        instance_id: String,
    },
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
    use std::{fs::File, io::Write, path::PathBuf};

    use log::{debug, error, info};
    use tokio::{
        sync::{
            mpsc::{self, Receiver, Sender},
            oneshot,
        },
        task::JoinHandle,
    };

    use super::{BenchmarkingError, Event};

    /// Start an emitter in a Tokio thread. Returns the channel through which the emitter can be fed
    /// events, a channel through which the emitter can be shut down, as well as the emitter's thread handle.
    pub fn start(
        emitter: Emitter,
    ) -> (
        Sender<Event>,
        oneshot::Sender<bool>,
        JoinHandle<Result<(), BenchmarkingError>>,
    ) {
        let (tx, rx) = mpsc::channel::<Event>(100);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<bool>();
        let handle = tokio::spawn(async move { emitter.run(rx, shutdown_rx).await });

        (tx, shutdown_tx, handle)
    }

    /// Starts a null emitter which behaves like a regular emitter, but discards all events
    /// passed to it.
    pub fn start_null_emitter() -> (
        Sender<Event>,
        oneshot::Sender<bool>,
        JoinHandle<Result<(), BenchmarkingError>>,
    ) {
        let (tx, mut rx) = mpsc::channel::<Event>(100);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<bool>();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        info!("Null-emitter shutting down. Nothing was achieved :)");
                        return Ok(())
                    }, // Terminate on shutdown signal
                    Some(_) = rx.recv() => {}, // Discard incoming events
                }
            }
        });

        (tx, shutdown_tx, handle)
    }

    /// New initializes a new emitter.
    ///
    /// An error is returned if opening its output file failed.
    pub fn new(outfile: &PathBuf) -> Result<Emitter, BenchmarkingError> {
        let emitter = {
            let fh = File::create(outfile.clone()).map_err(|e| BenchmarkingError::IOError(e))?;
            // We only care about the side-effect of creating (or truncating) the output file.
            drop(fh);

            Emitter {
                outfile: outfile.clone(),
            }
        };

        Ok(emitter)
    }

    pub struct Emitter {
        outfile: PathBuf,
    }

    impl Emitter {
        /// Start listening for events on the given channel, and write them to the output file. The
        /// emitter will keep running until a value is received via the shutdown channel.
        pub async fn run(
            &self,
            mut rx: Receiver<Event>,
            mut shutdown_rx: oneshot::Receiver<bool>,
        ) -> Result<(), BenchmarkingError> {
            // We re-open the file such that we can move the file handle into the thread.
            let mut fh = File::options()
                .append(true)
                .open(self.outfile.clone())
                .map_err(|e| BenchmarkingError::IOError(e))?;

            info!("Ready and waiting for events");
            loop {
                tokio::select! {
                    cmd = &mut shutdown_rx => {
                        match cmd {
                            Ok(_) => {
                                info!("Event listener received shutdown command. Terminating.");
                                return Ok(());
                            },
                            Err(e) => {
                                error!("Shutdown channel of event listener closed unexpectedly. Terminating.");
                                return Err(BenchmarkingError::InternalError(format!("{}", e)));
                            }
                        }
                    },

                    Some(event) = rx.recv() => {
                        debug!("Emitting event: {:?}", event);
                        // We'll unwrap here, to noisly faily should serialization fail
                        let data = serde_json::to_string(&event).unwrap();
                        writeln!(fh, "{}", data).unwrap();
                    },
                }
            }
        }
    }
}
