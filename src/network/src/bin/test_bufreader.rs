// #![feature(pin)]
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::io::{BufReader};
use std::error::Error;
// use futures::executor::block_on;
// use futures::stream::{self, StreamExt};
// use async_std::prelude::*;
// use std::io::Read;
// use tokio::fs::File;
// use tokio::io::AsyncReadExt; // for read_to_end()
// use tokio::io::{self, AsyncBufReadExt};
// use std::{thread, time, string};
// use std::io::{self, BufRead};
// use tokio::fs::File;
// use tokio::io::AsyncReadExt; // for read_to_end()

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    // // Read the contents of a file into a buffer:
    // let mut file = File::open("msgs.txt").await?;

    // let mut contents = vec![];
    // file.read_to_end(&mut contents).await?;

    // println!("len = {}", contents.len());

    // File must exist in current path before this produces output
    
    // if let Ok(lines) = read_lines("./msgs.txt") {
    //     // Consumes the iterator, returns an (Optional) String
    //     for line in lines {
    //         if let Ok(ip) = line {
    //             println!("{}", ip);
    //         }
    //     }
    // }
    // Ok(())

    // let file = File::open("msgs.txt")?;
    // let lines = io::BufReader::new(file).lines();
    // for line in lines {
    //     println!("line: {:?}", line);
    // }

    let f = File::open("./msgs.txt")?;
    let mut reader = BufReader::new(f);
    let mut line = String::new();
    let len = reader.read_line(&mut line)?;
    for line in reader.lines() {
        println!("line: {:?}", line);
    }

    Ok(())

    // const BUFFER_LEN: usize = 512;
    // let mut buffer = [0u8; BUFFER_LEN];
    // let mut file = File::open("msgs.txt")?;

    // let mut stdin = io::BufReader::new(io::stdin()).lines();

    // loop {
    //     tokio::select! {
    //         line = lines.next_line() => {

    //         }
    //         line = stdin.next_line() => {
    //             let line = line?.expect("stdin closed");
    //             // sends the input from the command line
    //             // send_floodsub_cmd_line(&mut swarm, &floodsub_topic, line);
    
    //             // a vec<u8> message is created and submitted when hitting "enter" (in the command line)
    //             // let my_msg: Vec<u8> = [0b01001100u8, 0b11001100u8, 0b01101100u8].to_vec();
    //             let my_msg: Vec<u8> = [].to_vec();
    //             println!("input");
    //             send_floodsub_msg(&mut swarm, &floodsub_topic, my_msg);                
    //         }
    //     }
    // }

    // loop {
    //     tokio::select! {
    //         read_count = file.read_exact(&mut buffer) => {
    //             println!("loop");

    //             // if read_count != BUFFER_LEN {
    //             //     break;
    //             // }
    //         }
    //         // let (item, stream) = stream.into_future().await;
    //         //     assert_eq!(Some(1), item);
    //         // () = reader.lines() => {
    //         //     // println!("file_line: {}", file_line);
    //         // }
    //     }
    // }
}

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}