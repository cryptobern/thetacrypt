use std::{thread, time, string};
use std::io::{self, BufRead};
use std::path::Path;
use std::io::{BufReader};
use std::fs::File;

async fn do_stuff_async() {
    // async work
    // thread::sleep(time::Duration::from_secs(5));
    // println!("hello rust");
    for i in 1..5 {
        thread::sleep(time::Duration::from_secs(1));
        println!("do_stuff_async {}", i);
    }
    // File must exist in current path before this produces output
    // if let Ok(lines) = read_lines("./msgs.txt").await {
    //     // Consumes the iterator, returns an (Optional) String
    //     for line in lines {
    //         if let Ok(ip) = line {
    //             println!("{}", ip);
    //         }
    //     }
    // }
}

async fn more_async_work() {
    // more here
    for i in 1..5 {
        thread::sleep(time::Duration::from_secs(1));
        println!("more_async {}", i);
    }
}

#[tokio::main]
async fn main() {
    tokio::spawn(do_stuff_async());
    tokio::spawn(more_async_work());

    // tokio::select! {
    //     _ = do_stuff_async() => {
    //         println!("do_stuff_async() completed first")
    //     }
    //     _ = more_async_work() => {
    //         println!("more_async_work() completed first")
    //     }
    // };
}

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
async fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>> where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}