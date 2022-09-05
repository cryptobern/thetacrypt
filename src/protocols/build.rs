fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
    .protoc_arg("--experimental_allow_proto3_optional")
    .extern_path(".scheme_types", "::cosmos_crypto::proto::scheme_types")
    .out_dir("./src/proto")
    .compile(&["./src/proto/protocol_types.proto"], &["./src/proto", "../src/proto"])?;
    Ok(())
}