fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
    .protoc_arg("--experimental_allow_proto3_optional")
    .out_dir("./src/proto")
    .protoc_arg("--experimental_allow_proto3_optional")
    .compile(&["./src/proto/blockchain_stub.proto"], &["./src"])?; 
    Ok(())
}