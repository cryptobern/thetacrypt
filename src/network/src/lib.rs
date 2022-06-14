pub mod lib {

    // get data type
    use std::any::type_name;
    
    pub fn type_of<T>(_: T) -> &'static str {
        type_name::<T>()
    }

    // get node ids from tendermint nodes in the network
    use std::error::Error;
    use reqwest;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    struct Response {
        listening: bool,
        peers: Vec<Peer>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct Peer {
        pub node_id: String,
        pub url: String,
    }

    pub async fn get_peers(address: String) -> Result<Vec<Peer>, Box<dyn Error>> {
        let req_url = address + "/net_info";
        let response = reqwest::get(req_url).await?.json::<Response>().await?;
        Ok(response.peers)
    }
}