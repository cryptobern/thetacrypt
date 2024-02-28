use tonic::async_trait;
use theta_protocols::interface::ProtocolError;

//Eventually this interface should be used by the executor. Add the terminate
#[async_trait]
pub trait ThresholdProtocol {
    async fn run(&mut self) -> Result<Vec<u8>, ProtocolError>;
    // async fn terminate(&mut self) -> Result<(), ProtocolError>; to add to close the channels 
    async fn terminate(&mut self) -> Result<(), ProtocolError>;
}