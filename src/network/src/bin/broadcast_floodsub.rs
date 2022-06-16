// use cosmos_crypto::dl_schemes::dl_groups::ed25519::Ed25519;
use futures::StreamExt;
// use core::num::dec2flt::parse;
use std::{error::Error, str::FromStr, string::ParseError};
use libp2p::{
    core::upgrade,
    floodsub::{self, Floodsub},
    identity,
    mdns::{Mdns},
    mplex,
    Multiaddr,
    noise,
    swarm::{SwarmBuilder, SwarmEvent},
    // `TokioTcpConfig` is available through the `tcp-tokio` feature.
    tcp::TokioTcpConfig,
    Transport,
    PeerId,
};
use floodsub::Topic;
use tokio::io::{self, AsyncBufReadExt};
// use std::str::FromStr;

use deliver::deliver::MyBehaviour;
use send::send::{send_floodsub_vecu8_msg, send_floodsub_cmd_line};
use network_info::local_node::{get_peer_info};
mod deliver;
mod send;
mod network_info;

use std::{thread, time};
use once_cell::sync::Lazy;
use network::lib::type_of;
// use std::fs::File;
// use std::path::Path;

static FLOODSUB_TOPIC: Lazy<Topic> = Lazy::new(|| Topic::new("share"));

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    // Create a random PeerId
    let id_keys = identity::Keypair::generate_ed25519();
    let mut peer_id = PeerId::from(id_keys.public());
    println!("Local peer id: {:?}", peer_id);

    // local RPC endpoint
    let my_rpc_addr = "http://127.0.0.1:26657";

    // get local PeerId
    match get_peer_info(my_rpc_addr.to_string()).await {
        Ok(response) => {
            let my_node_id = response.node_info.id;
            let my_pub_key = response.validator_info.pub_key.value;
            println!("local node id: {:#?}", my_node_id);
            println!("local node pub_key: {:#?}", my_pub_key);

            // --- try to convert pub_key / node_id into PubKey or PeerId ----

            // let my_peer = PeerId::from_bytes(response.node_info.id.as_bytes());
            // match PeerId::from_bytes(response.node_info.id.as_bytes()) {
            //     Ok(peer_id) => {
            //         println!("peer_id from bytes: {:?}", peer_id);
            //         println!("peer_id type: {:#?}", type_of(&peer_id));
            //     },
            //     Err(parse_err) => {
            //         println!("byte Error: {:?}", parse_err);
            //     },
            // }
            // let test_id: Vec<u8> = response.node_info.id.as_bytes().to_vec();
            // println!("node id type: {:#?}", type_of(&my_peer));
            // println!("node id type: {:#?}", type_of(&response.node_info.id.as_str()));

            let pub_key_vec = my_pub_key.as_bytes();
            // let pub_key = identity::PublicKey::from_protobuf_encoding(&pub_key_vec).unwrap();
            // println!("pub_key: {:#?}", pub_key);

            // let my_keys: identity::PublicKey = identity::PublicKey::Ed25519(response.validator_info.pub_key.value);
            // let mut bytes = std::fs::read(response.validator_info.pub_key.value).unwrap();
            // let key_pair = Keypair::rsa_from_pkcs8(&mut bytes);
            match identity::PublicKey::from_protobuf_encoding(pub_key_vec) {
                Ok(ok_pub_key) => println!("ok_pub_key: {:?}", ok_pub_key),
                Err(pub_key_error) => println!("pub key error: {}", pub_key_error),
            }
            // let pub_key2 = identity::PublicKey::from_protobuf_encoding(pub_key_vec).unwrap();

            // let my_pub_key = Ed25519::Keypair::from_pkcs8(&mut bytes);
            // peer_id = PeerId::from_str(response.node_info.id.as_str()).unwrap();
            // match PeerId::try_from(response.node_info.id.as_bytes().to_vec()) {
            // match PeerId::from_str(response.node_info.id.as_str()) {
            //     Ok(p_id) => {
            //         println!("peer_id from string: {:?}", p_id);
            //         println!("peer_id from string type: {}", type_of(p_id));
            //         peer_id = p_id;
            //     },
            //     Err(parse_err) => {
            //         println!("str Error: {:?}", parse_err);
            //         // let string2: String = String::from_utf8(parse_err.clone()).unwrap();
            //         // println!("error as string: {:?}", string2);
            //         peer_id = PeerId::from(id_keys.public());
            //     },
            // }
        },
        Err(err) => {
            println!("Error: {}", err);
        },
    }

    // Create a keypair for authenticated encryption of the transport.
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&id_keys)
        .expect("Signing libp2p-noise static DH keypair failed.");

    // Create a tokio-based TCP transport use noise for authenticated
    // encryption and Mplex for multiplexing of substreams on a TCP stream.
    let transport = TokioTcpConfig::new()
        .nodelay(true)
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(mplex::MplexConfig::new())
        .boxed();

    // Create a Swarm to manage peers and events.
    let mut swarm = {
        let mdns = Mdns::new(Default::default()).await?;
        let mut behaviour = MyBehaviour {
            floodsub: Floodsub::new(peer_id.clone()),
            mdns,
        };

        behaviour.floodsub.subscribe(FLOODSUB_TOPIC.clone());

        SwarmBuilder::new(transport, behaviour, peer_id)
            // We want the connection backgro&mut und tasks to be spawned onto the tokio runtime.
            .executor(Box::new(|fut| {
                tokio::spawn(fut);
            }))
            .build()
    };

    // Reach out to another node if specified
    if let Some(to_dial) = std::env::args().nth(1) {
        let addr: Multiaddr = to_dial.parse()?;
        swarm.dial(addr)?;
        println!("Dialed {:?}", to_dial);
    }

    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines();

    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;   

    loop {
        tokio::select! {
            // testing select! with other function
            // my_msg = do_stuff_async() => {
            //     match my_msg {
            //         Some(m) => {
            //             send_floodsub_vecu8_msg(&mut swarm, &FLOODSUB_TOPIC, m);
            //         },
            //         None => println!("NONE"),
            //     }
            //     // let my_msg: Vec<u8> = [0b01001100u8, 0b11001100u8, 0b01101100u8].to_vec();
            //     // let my_msg = "hello".to_string();
            //     // send_floodsub_cmd_line(&mut swarm, &FLOODSUB_TOPIC, my_msg);
            // }
            line = stdin.next_line() => {
                let line = line?.expect("stdin closed");
                // sends the input from the command line
                send_floodsub_cmd_line(&mut swarm, &FLOODSUB_TOPIC, line);            
            }
            event = swarm.select_next_some() => {
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    println!("Listening on {:?}", address);
                }
                // else {
                //     println!("-------------------------------------");
                //     println!("other event {:?}", event);
                //     println!("event type {:?}", type_of(event));
                //     println!("-------------------------------------");
                // }
            }
        }
    }

}

// async fn swarm_event(swarm: &mut Swarm<MyBehaviour>) {
//     loop {
//         tokio::select! {
//             event = swarm.select_next_some() => {
//                 if let SwarmEvent::NewListenAddr { address, .. } = event {
//                     println!("Listening on {:?}", address);
//                 }
//             }
//         }
//     }
// }

// async fn init_buffer() -> std::io::Result<()> {
//     let shares = [[0b01001100u8, 0b11001100u8, 0b01101100u8].to_vec(),
//                             [0b01001100u8, 0b01001100u8, 0b01101100u8].to_vec(),
//                             [0b01101100u8, 0b11001100u8, 0b01101100u8].to_vec(),
//                             [0b01001100u8, 0b11001100u8, 0b01001100u8].to_vec(),
//                             [0b01101100u8, 0b11001100u8, 0b01101100u8].to_vec()];
    
//     let f = File::open("msgs.txt")?;
//     let mut reader = BufReader::new(f);

//     let mut line = String::new();
//     let len = reader.read_line(&mut line)?;
//     // println!("First line is {len} bytes long");

//     println!("First line is: {line}");
//     Ok(())
// }

async fn do_stuff_async() -> Option<Vec<u8>> {
    let mut vec = Vec::new();
    vec.push(2);
    vec.push(5);
    vec.push(1);
    vec.push(222);
    let opt_vec: Option<Vec<u8>> = Some(vec);
    thread::sleep(time::Duration::from_secs(5));
    return opt_vec;
}