fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
    .protoc_arg("--experimental_allow_proto3_optional")
    .out_dir("./src")
    .type_attribute("ThresholdSchemeCode", "#[derive(serde::Serialize, serde::Deserialize)]")
    .type_attribute("GroupCode", "#[derive(serde::Serialize, serde::Deserialize)]")
    // .type_attribute("PublicKeyEntry", "#[derive(Debug)]")
    .protoc_arg("--experimental_allow_proto3_optional")
    .compile(&["./src/protocol_types.proto","./src/scheme_types.proto"], &["./src"])?; 
    Ok(())
}

// tonic_build::configure()
//     .out_dir("./src/proto")
//     .type_attribute("ThresholdScheme", "#[derive(serde::Serialize, serde::Deserialize)]")
//     .type_attribute("Group", "#[derive(serde::Serialize, serde::Deserialize)]")
//     .type_attribute("PublicKeyEntry", "#[derive(Debug)]")
//     .compile(&["./src/proto/scheme_types.proto"], &["./src/proto"])?;
//     Ok(())
