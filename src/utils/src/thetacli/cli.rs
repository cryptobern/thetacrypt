use clap::{Parser, ValueEnum, Subcommand, Args};

#[derive(Parser, Debug)]
#[command(version = "1.0", about, long_about = None)]
#[command(propagate_version = true)]
pub struct ThetaCliArgs {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    keygen(KeyGenArgs),
    enc(EncArgs),
    verify(VerifyArgs)
}

#[derive(Args, Debug)]
pub struct KeyGenArgs {
    #[arg(short, 
        help = "Threshold (minimum number of parties that need to collaborate)", 
    )]
    pub k: u16,
    #[arg(
        short,
        help = "Number of parties"
    )]
    pub n: u16,
    #[arg(
        short,
        long,
        help = "A list of comma separated elements of the format 'scheme-group', where 'scheme' is one of the following:\n\t encryption schemes: sg02, bz03\n\t signature schemes: bls04, frost, sh00\n\t coin schemes: cks05\nand 'group' is one of\n\t 'bls12381', 'bn254', 'ed25519', 'rsa512', 'rsa1024', 'rsa2048'.\nexample: sg02-bls12381,bz03-ed25519",
    )]
    pub subjects: String,
    #[arg(
        short,
        long,
        help = "Directory to store the generated keys in",
    )]
    pub dir: String,
    #[arg(short,
        long, 
        help = "Append a new key to existing ones",
        default_value_t = false
    )]
    pub append: bool,
}
#[derive(Args, Debug)]
pub struct EncArgs {
    #[arg(
        short, 
        long,
        help = "The path to the input file"
    )]
    pub infile: String,
    #[arg(
        short,
        long,
        help = "The path to the key file",
    )]
    pub key_path: String,
    #[arg(
        short,
        long,
        help = "The encryption label"
    )]
    pub label: String,
    #[arg(
        short,
        long,
        help = "The output path"
    )]
    pub outfile: String,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    #[arg(
        short,
        long,
        help = "The path to the public key file"
    )]
    pub key_path: String,
    #[arg(
        short,
        long,
        help = "The path to the file containing the message"
    )]
    pub message_path: String,
    #[arg(
        short,
        long,
        help = "The path to the file containing the signature",
    )]
    pub signature_path: String,
}