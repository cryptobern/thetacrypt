
pub struct Bls04ThresholdVRF {
    pi: Bls04ThresholdSignature,
    vrf: GroupElement, // VRF output, result of an hash function to define
}

// See if we need to define new public keys or we can use bls04 existing ones

#[derive(Clone, DlShare, PartialEq)]
pub struct Bls04VRFShare {
    pi_i: Bls05SignatureShare,
}

impl Bls04VRFShare{
    pub fn get_label(&self) -> &[u8] {
        self.pi_i.get_label()
    }

    pub fn get_scheme(&self) -> &ThresholdScheme {
        ThresholdScheme::Bls04VRF
    }
}

