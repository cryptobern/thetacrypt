fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
    .out_dir("src/pb")
    .type_attribute("ThresholdCipher", "#[derive(serde::Serialize, serde::Deserialize)]")
    .type_attribute("DlGroup", "#[derive(serde::Serialize, serde::Deserialize)]")
    .compile(&["proto/requests.proto"], &["proto"])?;
    Ok(())
}