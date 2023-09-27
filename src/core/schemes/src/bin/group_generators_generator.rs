use mcore::{hash256::HASH256};
use theta_schemes::{group::{GroupElement}, scheme_types_impl::GroupDetails};
use theta_proto::scheme_types::Group;

// This binary can be used to generate a second generator for the given cyclic EC-based groups.
// The generator is choosen by mapping the SHA256 hash of the string
// "thetacrypt_<commit ID of Linux 6.4>"" to a point on the respective elliptic curve.
// That point is then chosen as generator.
fn main(){
    let groups: Vec<Group> = vec![Group::Bls12381, Group::Bn254];

    // Linux version 6.4 commit hash
    // https://github.com/torvalds/linux/commit/6995e2de6891c724bfeb2db33d7b87775f913ad1
    let seed: &str = "thetacrypt_6995e2de6891c724bfeb2db33d7b87775f913ad1";

    let bytes = seed.as_bytes();

    let mut hasher = HASH256::new();
    hasher.process_array(bytes);

    // Hash will be 14fad7f1b49b586b13149dd8b07cb67f89c416e3bd216e12e110ae66680c44a1
    let hash = hasher.hash();

    for group in groups {
        let computed_generator = GroupElement::new_hash(&group, &hash);
        let predefined_generator = group.get_alternate_generator();
        println!("computed generator for group {}: {}", group.as_str_name(), computed_generator.to_string());
        println!("predefined generator for group {}: {}", group.as_str_name(), predefined_generator.to_string());

        // Output:
        // computed generator for group Bls12381: (15923CA30404617E50806EC015F2597157B75D0BD342EF2A5FC1CB4041E89AC356806FD04CCC0B118C803F0006CD9413,1511F2A6BBF3F63561A41D3A49CCFF50DF35B9AD116AC539D1AEBDFC3873AEB5F6EAACADB00C4B36EFD000904BC12833)
        // predefined generator for group Bls12381: (15923CA30404617E50806EC015F2597157B75D0BD342EF2A5FC1CB4041E89AC356806FD04CCC0B118C803F0006CD9413,1511F2A6BBF3F63561A41D3A49CCFF50DF35B9AD116AC539D1AEBDFC3873AEB5F6EAACADB00C4B36EFD000904BC12833)
        // computed generator for group Bn254: (0568E3BA9ADD8FB3842403FF1E7D04AEADBE38992C2CDB3AE8F520398DFBF603,1215AAA15E82FAFC3522034DE4F3FE3C18075AFE109A413BAAFC47577F76D640)
        // predefined generator for group Bn254: (0568E3BA9ADD8FB3842403FF1E7D04AEADBE38992C2CDB3AE8F520398DFBF603,1215AAA15E82FAFC3522034DE4F3FE3C18075AFE109A413BAAFC47577F76D640)

        // Assert that the predefined alternative generator (defined in code) and the computed one match
        // This means that the generators defined in code have been generated using the method in this program.
        assert_eq!(computed_generator, predefined_generator);
    }
}