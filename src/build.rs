fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
    .out_dir("./src/proto")
    .type_attribute("ThresholdScheme", "#[derive(serde::Serialize, serde::Deserialize)]")
    .type_attribute("Group", "#[derive(serde::Serialize, serde::Deserialize)]")
    .compile(&["./src/proto/scheme_types.proto"], &["./src/proto"])?;
    // .compile(&["src/src/proto/requests.proto", "src/src/proto/types.proto"], &["proto"])?;
    Ok(())
}