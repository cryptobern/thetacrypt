use super::pedersen::{PedersenCommitment, PedersenCommitmentParams};

pub enum Commitment {
    Pedersen(PedersenCommitment),
}

pub enum CommitmentParams {
    Pedersen(PedersenCommitmentParams),
}

impl Commitment {
    pub fn commit(params: &CommitmentParams) -> Self {
        match params {
            CommitmentParams::Pedersen(pedersen_params) => {
                return Commitment::Pedersen(PedersenCommitment::commit(pedersen_params));
            }
        }
    }

    pub fn verify(self, params: &CommitmentParams) -> bool {
        match self {
            Commitment::Pedersen(pedersen) => match params {
                CommitmentParams::Pedersen(pedersen_params) => {
                    return pedersen.verify(pedersen_params);
                }
            },
        }
    }
}