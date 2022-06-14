use futures::StreamExt;
use std::{error::Error};
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
    PeerId, Swarm,
};
use floodsub::Topic;
use tokio::io::{self, AsyncBufReadExt};

use deliver::deliver::MyBehaviour;
use send::send::{send_floodsub_msg, send_floodsub_cmd_line, send_async};
mod deliver;
mod send;
use std::{thread, time, string};
use once_cell::sync::Lazy;
use network::lib::type_of;
use std::fs::File;
use std::path::Path;

// use std::{thread, time, string};

static FLOODSUB_TOPIC: Lazy<Topic> = Lazy::new(|| Topic::new("share"));

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    // Create a random PeerId
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(id_keys.public());
    println!("Local peer id: {:?}", peer_id);

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

    // Create a Floodsub topic
    // let floodsub_topic = Topic::new("shares");

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
            my_msg = do_stuff_async() => {
                match my_msg {
                    Some(m) => {
                        send_floodsub_msg(&mut swarm, &FLOODSUB_TOPIC, m);
                    },
                    None => println!("NONE"),
                }
                // let my_msg: Vec<u8> = [0b01001100u8, 0b11001100u8, 0b01101100u8].to_vec();
                // let my_msg = "hello".to_string();
                // send_floodsub_cmd_line(&mut swarm, &FLOODSUB_TOPIC, my_msg);
            }
            line = stdin.next_line() => {
                let line = line?.expect("stdin closed");
                // sends the input from the command line
                send_floodsub_cmd_line(&mut swarm, &FLOODSUB_TOPIC, line);

                // a vec<u8> message is created and submitted when hitting "enter" (in the command line)
                // let my_msg: Vec<u8> = [0b01001100u8, 0b11001100u8, 0b01101100u8].to_vec();
                // let my_msg: Vec<u8> = [].to_vec();
                // println!("input");
                // send_floodsub_msg(&mut swarm, &FLOODSUB_TOPIC, my_msg);                
            }
            event = swarm.select_next_some() => {
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    println!("Listening on {:?}", address);
                // } if let SwarmEvent::Flood = event {
                //     println!("floddsubmessage {:?}", event);
                } else {
                    println!("-------------------------------------");
                    println!("other event {:?}", event);
                    println!("event type {:?}", type_of(event));
                    println!("-------------------------------------");
                }
            }
        }
    }

    // Ok(())

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