fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
    .protoc_arg("--experimental_allow_proto3_optional")
    .out_dir("./src")
    .protoc_arg("--experimental_allow_proto3_optional")
    .compile(&["./src/protocol_types.proto","./src/scheme_types.proto"], &["./src"])?; 
    Ok(())
}