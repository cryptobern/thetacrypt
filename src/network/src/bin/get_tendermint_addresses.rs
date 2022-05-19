// use std::error::Error;

// #[tokio::main]
// pub async fn main() -> Result<(), Box<dyn Error>> {
//     network::get_addresses();

//     Ok(())
// }

use reqwest;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // let mut map = HashMap::new();
    // map.insert("lang", "rust");
    // map.insert("body", "json");

    let client = reqwest::Client::new();
    // let res = client.post("http://127.0.0.1:26657/net_info")
    //     .json(&map)
    //     .send()
    //     .await?;
    // println!("{:#?}", res);

    let response = client
        .post("http://127.0.0.1:26657/net_info")
        .header("ACCEPT", "application/json")
        .header("CONTENT_TYPE", "application/json")
        // .json(&map)
        .send()
        .await?
        // .unwrap();
        .text()
        .await?;
    println!("{:#?}", response);

    Ok(())
}