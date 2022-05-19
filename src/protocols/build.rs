fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
    .type_attribute("ThresholdCipher", "#[derive(serde::Serialize, serde::Deserialize)]")
    .type_attribute("DlGroup", "#[derive(serde::Serialize, serde::Deserialize)]")
    .compile(&["proto/requests.proto"], &["proto"])?;
    // .out_dir("another_crate/src/pb")
    Ok(())
}