use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version = "1.0", about, long_about = None)]
#[command(propagate_version = true)]
pub struct ThetaCliArgs {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Locally generate keys for threshold schemes
    Keygen(KeyGenArgs),
    /// Encrypt data using threshold encryption
    Enc(EncArgs),
    /// Verify threshold signatures
    Verify(VerifyArgs),
    /// Manipulate keystores
    Keystore(KeystoreArgs),
}

#[derive(Args, Debug)]
pub struct KeyGenArgs {
    #[arg(
        short,
        help = "Threshold (minimum number of parties that need to collaborate)"
    )]
    pub k: u16,
    #[arg(short, help = "Number of parties")]
    pub n: u16,
    #[arg(
        short,
        long,
        help = "A list of comma separated elements of the format 'scheme-group', where 'scheme' is one of the following:\n\t encryption schemes: sg02, bz03\n\t signature schemes: bls04, frost, sh00\n\t coin schemes: cks05\nand 'group' is one of\n\t 'bls12381', 'bn254', 'ed25519', 'rsa512', 'rsa1024', 'rsa2048', 'rsa4096'.\nexample: sg02-bls12381,bz03-ed25519. \nA single string 'all' should be used to create all possible keys."
    )]
    pub subjects: String,
    #[arg(short, long, help = "Directory to store the generated keys in")]
    pub output: String,
    #[arg(
        long,
        help = "Option to create a completely new set of keys, overwriting the chosen keyfile if it already existed",
        default_value_t = false
    )]
    pub new: bool,
}
#[derive(Args, Debug)]
pub struct EncArgs {
    #[arg(short, long, help = "The path to the input file")]
    pub infile: Option<String>,
    #[arg(long, help = "The path to the public key file")]
    pub pubkey: Option<String>,
    #[arg(long, help = "The path to the keystore")]
    pub keystore: Option<String>,
    #[arg(short, long, help = "The key id")]
    pub key_id: Option<String>,
    #[arg(short, long, help = "The encryption label")]
    pub label: String,
    #[arg(short, long, help = "The output file (use - for stdout)")]
    pub output: String,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    #[arg(short, long, help = "The path to the file containing the message")]
    pub message_path: String,
    #[arg(short, long, help = "The path to the file containing the signature")]
    pub signature_path: String,
    #[arg(long, help = "The path to the public key file")]
    pub pubkey: Option<String>,
    #[arg(long, help = "The path to the keystore")]
    pub keystore: Option<String>,
    #[arg(short, long, help = "The key id")]
    pub key_id: Option<String>,
}

#[derive(Args, Debug)]
pub struct KeystoreArgs {
    #[arg(help = "The action to perform")]
    pub action: String,
    #[arg(help = "The path to the keystore")]
    pub keystore: String,
    #[arg(
        long,
        help = "The address of the network node (example https://127.0.0.1:1234)"
    )]
    pub address: Option<String>,
    #[arg(
        long,
        help = "Option to overwrite the existing keystore",
        default_value_t = false
    )]
    pub new: bool,
    #[arg(long, help = "Path to input key file")]
    pub input: Option<String>,
}
