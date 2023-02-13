use tendermint_abci::ServerBuilder;
use structopt::StructOpt;
use abci_app::fair_order_app::{FairOrderApp, FairOrderDriver};
use tracing_subscriber::filter::LevelFilter;

#[derive(Debug, StructOpt)]
struct Opt {
    /// Bind the TCP server to this host.
    #[structopt(long, default_value = "127.0.0.1")]
    listen_ip: String,

    /// Bind the TCP server to this port.
    #[structopt(long, default_value = "26658")]
    listen_port: u16,

    /// The default server read buffer size, in bytes, for each incoming client
    /// connection.
    #[structopt(long, default_value = "1048576")]
    read_buf_size: usize,

    /// Increase output logging verbosity to DEBUG level.
    #[structopt(long)]
    verbose: bool,

    /// Suppress all output logging (overrides --verbose).
    #[structopt(long)]
    quiet: bool,

    /// IP where the threshold crypto library is running.
    #[structopt(long, default_value = "127.0.0.1")]
    tcl_ip: String,
    
    /// IP where the threshold crypto library is listening.
    #[structopt(long, default_value = "51000")]
    tcl_port: u16,
 
}

#[tokio::main]
async fn main() {
    let opt: Opt = Opt::from_args();
    let log_level = if opt.quiet {
        LevelFilter::OFF
    } else if opt.verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    tracing_subscriber::fmt().with_max_level(log_level).init();

    let (app, driver) = FairOrderApp::new(opt.tcl_ip, opt.tcl_port).await;
    let server = ServerBuilder::new(opt.read_buf_size)
        .bind(format!("{}:{}", opt.listen_ip, opt.listen_port), app)
        .unwrap();
    std::thread::spawn(move || async_std::task::block_on(async { driver.run().await; }));
    println!(">> ABCI server listening on {:?}:{:?}.", opt.listen_ip, opt.listen_port);
    server.listen().unwrap();
}
