use network::config::tendermint_net_config::config_service::*;
use network::config::tendermint_net_config::rpc_requests::rpc_net_info::get_tendermint_net_info;
use network::config::tendermint_net_config::rpc_requests::rpc_status::get_tendermint_status;

const CONFIG_PATH: &str = "../src/config/tendermint_net_config/config.toml";

#[tokio::main]
async fn main() {
    
    // load config file
    println!("wd: {:?}", std::env::current_dir());
    let config = load_config(CONFIG_PATH.to_string());
    println!("config: {:?}", config);
    
    let p2p_listen_addr = get_p2p_listen_addr(&config);
    println!("p2p listen addr: {:?}", p2p_listen_addr);

    let rpc_listen_addr = get_rpc_listen_addr(&config);
    println!("rpc listen addr: {:?}", rpc_listen_addr);
    
    let test_addr = "http://127.0.0.1:26657";
    get_node_ips(test_addr.to_string()).await;

    // // test tendermint RPC endpoint /net_info with reqwest
    // match get_tendermint_net_info(test_addr.to_string()).await {
    //     Ok(response) => {
    //         // println!("{:#?}", response);
    //         println!("no. of other peers {:#?}", response.result.n_peers);
    //         for peer in response.result.peers {
    //             println!("node id: {:#?}", peer.node_id);
    //             println!("node url: {:#?}", peer.url);
    //         }
    //     },
    //     Err(err) => println!("Error: {}", err),
    // }

    // // test tendermint RPC endpoint /status with reqwest
    // match get_tendermint_status(test_addr.to_string()).await {
    //     Ok(response) => {
    //         println!("{:#?}", response);
    //         println!("{:#?}", response.result);
    //     },
    //     Err(err) => println!("Error: {}", err),
    // }
}