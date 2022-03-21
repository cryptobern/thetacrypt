/// print a vector of bytes to the console
pub fn printbinary(array: &[u8], caption: Option<&str>) {
    if caption.is_some() {
        print!("{}", caption.unwrap());
    }
    for i in 0..array.len() {
        print!("{:02X}", array[i])
    }
    println!("")
}



/// convert a vector of bytes to an ASCII string
pub fn hex2string(msg: &Vec<u8>) -> String {
    let mut res: String = String::new();
    for i in 0..msg.len() {
        res.push(msg[i] as char);
    }

    res
}