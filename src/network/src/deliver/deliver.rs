pub struct DeliverMessage<T> {
    pub from: u32,
    pub msg: T,
}
impl<T> DeliverMessage<T> {
    pub fn deliver(&self) {
        println!("deliver msg from: {}", &self.from);
    }
}