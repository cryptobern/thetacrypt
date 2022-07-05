use network::network_info::rpc_net_info::get_tendermint_net_info;
use network::network_info::rpc_status::get_tendermint_status;

#[tokio::main]
async fn main() {
    let test_addr = "http://127.0.0.1:26660";

    // test tendermint RPC endpoint /net_info with reqwest
    match get_tendermint_net_info(test_addr.to_string()).await {
        Ok(response) => {
            // println!("{:#?}", response);
            println!("no. of other peers {:#?}", response.result.n_peers);
            for peer in response.result.peers {
                println!("node id: {:#?}", peer.node_id);
                println!("node url: {:#?}", peer.url);
            }
        },
        Err(err) => println!("Error: {}", err),
    }

    // test tendermint RPC endpoint /status with reqwest
    match get_tendermint_status(test_addr.to_string()).await {
        Ok(response) => {
            println!("{:#?}", response);
            println!("{:#?}", response.result);
        },
        Err(err) => println!("Error: {}", err),
    }
}