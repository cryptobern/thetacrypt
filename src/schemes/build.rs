fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
    .out_dir("./src/proto")
    .type_attribute("ThresholdScheme", "#[derive(serde::Serialize, serde::Deserialize)]")
    .type_attribute("Group", "#[derive(serde::Serialize, serde::Deserialize)]")
    .type_attribute("PublicKeyEntry", "#[derive(Debug)]")
    .compile(&["./src/proto/scheme_types.proto"], &["./src/proto"])?;
    Ok(())
}