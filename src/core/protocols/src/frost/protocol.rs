use std::{collections::HashMap, f32::consts::E, sync::Arc};

use log::{debug, error, info};
use theta_network::types::message::NetMessage;
use theta_schemes::{
    dl_schemes::{
        commitments::interface::Commitment,
        signatures::frost::{
            assemble, commit, partial_sign, verify_share, FrostOptions, FrostPrivateKey,
            FrostSignature, FrostSignatureShare, Nonce, PublicCommitment,
        },
    }, groups::group::GroupElement, interface::{DlShare, SchemeError, Serializable, Signature}, keys::keys::PrivateKeyShare, rand::{RngAlgorithm, RNG}
};

use crate::interface::{ProtocolError, ThresholdRoundProtocol};

use super::message_types::{FrostData, FrostMessage};

static NUM_PRECOMPUTATIONS: usize = 10;

#[derive(PartialEq, Clone, Debug)]
pub struct FrostProtocol {
    round: u8,
    key: FrostPrivateKey,
    label: Vec<u8>,
    msg: Vec<u8>,
    nonce: Option<Nonce>,
    commitment: Option<PublicCommitment>,
    commitment_list: HashMap<u16, PublicCommitment>,
    precomputation_list: Vec<FrostPrecomputation>,
    group_commitment: Option<GroupElement>,
    share: Option<FrostSignatureShare>,
    shares: HashMap<u16, FrostSignatureShare>,
    finished: bool,
    options: FrostOptions,
    signer_group: SignerGroup,
}

impl ThresholdRoundProtocol<NetMessage> for FrostProtocol {
    // Define the concrete type for the ProtocolMessage
    type ProtocolMessage = FrostMessage;

    fn update(&mut self, message: FrostMessage) -> Result<(), ProtocolError> {
        info!("Update: round {:?}", self.round);
        match message.data {
            FrostData::Commitment(result) => {
                if let FrostOptions::PrecomputeOnly = self.options {
                    // ignore round one results if only precomputing
                    return Ok(());
                }

                // only accept first commitment for each node (id should be authenticated in the network layer)
                // and id has to be in the signer group
                if self.signer_group.contains(&message.id)
                    && !self.commitment_list.contains_key(&message.id)
                {
                    self.commitment_list.insert(message.id, result.clone());
                    info!("Inserted commitment with id {:?}", message.id);
                }

                Ok(())
            }
            FrostData::Share(share) => {
                if self.signer_group.contains(&message.id) && !self.shares.contains_key(&message.id)
                {
                    let mut commitment_list: Vec<PublicCommitment> =
                        self.commitment_list.values().cloned().collect();
                    
                    let result = verify_share(
                        &share,
                        &self.key.get_public_key(),
                        &self.msg,
                        &mut commitment_list,
                    );
                    if result.is_err() {
                        error!("invalid share with id {}: error: {:?}", &message.id, result.err());
                        return Err(ProtocolError::InternalError);
                    } 

                    if !result.unwrap() {
                        error!("invalid share with id {}", &message.id);
                        return Err(ProtocolError::InvalidShare);
                    }

                    self.shares.insert(message.id, share.clone());
                }

                Ok(())
            }
            FrostData::Precomputation(precomputations) => {
                if precomputations.len() == 0 {
                    return Err(ProtocolError::InvalidShare);
                }

                info!("precomp id: {}", message.id);
                if self.signer_group.contains(&message.id) {
                    let mut p: Vec<PublicCommitment>;
                    p = precomputations.clone();

                    // if we should sign and do a precomputation round, pop the first commitment from the stack to use for
                    // the signature in the current execution
                    if self.options == FrostOptions::Precomputation {
                        p = precomputations.clone();
                        let comm = p.pop().unwrap();
                        info!("use first precomp with id {}", message.id);
                        self.commitment_list.insert(message.id, comm);
                    }

                    if p.len() > 0 {
                        for i in 0..p.len() {
                            if self.precomputation_list.len() > i {
                                self.precomputation_list[i].insert(message.id, p[i].clone());
                            }
                        }
                    }
                }

                Ok(())
            }
            FrostData::Default => Err(ProtocolError::InternalError), // Default should not be received
        }
    }
    /*
    task: check whether we have all the necessary material to execute the next iteration of self.do_round()
     */
    fn is_ready_for_next_round(&self) -> bool {
        info!("is_ready_for_next_round: round {:?}", self.round);
        match self.round {
            1 => {
                debug!("party {:?} commitment list len: {}",self.key.get_share_id(), self.commitment_list.len());
                if self.commitment_list.len() >= self.key.get_threshold() as usize {
                    //checks if the commitments in the list are from the signing grup list
                    if let Option::Some(_) = self
                        .signer_group
                        .get_vec()
                        .iter()
                        .find(|f| !self.commitment_list.contains_key(&f)) // notice '!' it will stop as soon as it finds that a signer is NOT present
                    {
                        return false;
                    }
                    return true;
                }
                return false;
            }
            2 => {
                debug!("shares list len: {}", self.shares.len());
                if self.shares.len() >= self.key.get_threshold() as usize {
                    if let Option::Some(_) = self
                        .signer_group
                        .get_vec()
                        .iter()
                        .find(|f| !self.shares.contains_key(&f))
                    {
                        return false;
                    }
                    return true;
                }
                return false;
            }
            _ => return false,
        }
    }

    /*
       task: execute one round of the protocol, call the necessary methods of the primitive according to the current round
       returns: FrostRoundResult if execution was successful
                SchemeError::InvalidRound if all roun
    */
    fn do_round(&mut self) -> Result<FrostMessage, ProtocolError> {
        //TODO: handle the case in which the current node is not in the signer group 
        //      the node can still collect the material and assemple the signature
        //      But the do round will not produce anything, so we need a void message or something
        info!("do_round: : round {:?}", self.round);
        if self.round == 0 {
            let mut data = FrostData::Default;
            let mut message = FrostMessage::default();

            if (self.options != FrostOptions::NoPrecomputation) {
                data = self.precompute();
            } else {
                
                // Do the computation just if the node is in the signer group
                if self.signer_group.contains(&self.key.get_share_id())
                && !self.commitment_list.contains_key(&self.key.get_share_id())
            {   
                let (comm, nonce) = commit(&self.key, &mut RNG::new(RngAlgorithm::OsRng));
                self.nonce = Some(nonce);
                self.commitment = Some(comm.clone());

                self.commitment_list.insert(self.key.get_share_id(), comm.clone());
                info!("Inserted commitment with id {:?}", self.key.get_share_id());

                data = FrostData::Commitment(comm);
            }
            }

            self.round += 1;

            message = FrostMessage {
                id: self.key.get_share_id(),
                data,
            };

        

            return Ok(message);
        } else if self.round == 1 {
            let mut commitment_list: Vec<PublicCommitment> =
                self.commitment_list.values().cloned().collect();

            let res = partial_sign(
                &self.nonce.clone().unwrap(),
                &mut commitment_list,
                &self.msg,
                &self.key,
                self.key.get_share_id(),
            );
            if res.is_ok() {
                self.round += 1;

                let (share, group_commitment) = res.unwrap();
                self.group_commitment = Some(group_commitment);

                if self.signer_group.contains(&self.key.get_share_id()) && !self.shares.contains_key(&self.key.get_share_id()){
                    self.shares.insert(self.key.get_share_id(), share.clone());
                }

                let message = FrostMessage {
                    id: self.key.get_share_id(),
                    data: FrostData::Share(share),
                };
                return Ok(message);
            }

            return Err(ProtocolError::SchemeError(res.unwrap_err()));
        }

        Err(ProtocolError::InvalidRound)
    }

    fn is_ready_to_finalize(&self) -> bool {
        if self.shares.len() == self.key.get_threshold() as usize {
            // check if we have all required shares to assemble signature
            if let Option::Some(_) = self
                .signer_group
                .signer_identifiers
                .iter()
                .find(|i| !self.shares.contains_key(&i))
            {
                return false; // if not, just return Ok
            }

            return true;
        }

        false
    }

    fn finalize(&mut self) -> Result<Vec<u8>, crate::interface::ProtocolError> {
        let group_commitment = self.group_commitment.clone().unwrap();
        let shares = self.shares.values().cloned().collect();
        let sig = assemble(&group_commitment, &self.key, &shares);
        self.finished = true;
        let serialized_sig = Signature::Frost(sig).to_bytes();
        Ok(serialized_sig.unwrap())
    }
}

impl FrostProtocol {
    pub fn new(
        key: Arc<PrivateKeyShare>,
        msg: &[u8],
        label: &[u8],
        options: FrostOptions,
        precomputation: Option<FrostPrecomputation>,
    ) -> Self {
        let k = if let PrivateKeyShare::Frost(x) = key.as_ref() {
            x
        } else {
            panic!("");
        };
        if precomputation.is_none() {
            return Self {
                round: 0,
                msg: msg.to_vec(),
                label: label.to_vec(),
                shares: HashMap::new(),
                key: k.clone(),
                nonce: Option::None,
                commitment: Option::None,
                precomputation_list: Vec::new(),
                commitment_list: HashMap::new(),
                group_commitment: None,
                share: None,
                finished: false,
                options,
                signer_group: SignerGroup::new(key.get_threshold()),
            };
        }
        let precomputation = precomputation.unwrap();
        Self {
            round: 1,
            msg: msg.to_vec(),
            label: label.to_vec(),
            shares: HashMap::new(),
            key: k.clone(),
            nonce: Option::Some(precomputation.nonce),
            commitment: precomputation.commitments.get(&key.get_share_id()).cloned(),
            precomputation_list: Vec::new(),
            commitment_list: precomputation.commitments,
            group_commitment: None,
            share: None,
            finished: false,
            options,
            signer_group: SignerGroup::new(key.get_threshold()),
        }
    }

    pub fn set_label(&mut self, label: &[u8]) {
        self.label = label.to_vec();
    }

    pub fn get_label(&self) -> Vec<u8> {
        return self.label.clone();
    }

    pub fn set_commitment(&mut self, comm: &PublicCommitment) {
        self.commitment = Some(comm.clone());
    }

    /*
    task: return the gathered precomputations (e.g. commitments) from round 1 of the protocol

    returns: a vector of NUM_PRECOMPUTATIONS hash maps containing the commitments if successful
             a SchemeError::WrongState if precomputation is not yet finished or has failed
     */
    fn get_precomputations(&self) -> Result<Vec<FrostPrecomputation>, SchemeError> {
        if self.precomputation_list.len() > 1 && self.finished {
            return Ok(self.precomputation_list.clone());
        }

        Err(SchemeError::WrongState)
    }

    fn precompute(&mut self) -> FrostData {
        let mut commitments = Vec::new();
        for i in 0..NUM_PRECOMPUTATIONS {
            let (comm, nonce) = commit(&self.key, &mut RNG::new(RngAlgorithm::OsRng));

            commitments.push(comm.clone());
            let precompute = FrostPrecomputation::new(
                self.signer_group.clone(),
                self.key.get_share_id(),
                nonce,
                comm,
            );
            self.precomputation_list.push(precompute);
        }

        FrostData::Precomputation(commitments)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct SignerGroup {
    signer_identifiers: Vec<u16>,
}

impl SignerGroup {
    /* creates a new signer group with ids from 1 to n */
    // TODO: create a function that generates a random signer group given the instance_id
    pub fn new(n: u16) -> Self {
        let signer_identifiers: Vec<u16> = (1..n + 1).collect();
        Self { signer_identifiers }
    }

    /* creates a new signer group from a vector of ids */
    pub fn from_vec(ids: &Vec<u16>) -> Self {
        Self {
            signer_identifiers: ids.clone(),
        }
    }

    /* include id in group */
    pub fn include(&mut self, id: &u16) {
        self.signer_identifiers.push(id.clone());
    }

    /* exclude id from group */
    pub fn exclude(&mut self, id: &u16) {
        self.signer_identifiers.retain(|v| !v.eq(id));
    }

    /* check if id is part of group */
    pub fn contains(&self, id: &u16) -> bool {
        self.signer_identifiers.contains(id)
    }

    /* return vector of signer identifiers */
    pub fn get_vec(&self) -> &Vec<u16> {
        &self.signer_identifiers
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FrostPrecomputation {
    group: SignerGroup,
    nonce: Nonce,
    commitments: HashMap<u16, PublicCommitment>,
}

impl FrostPrecomputation {
    fn new(group: SignerGroup, id: u16, nonce: Nonce, commitment: PublicCommitment) -> Self {
        let mut commitments = HashMap::new();
        commitments.insert(id, commitment);
        Self {
            group,
            nonce,
            commitments,
        }
    }

    fn insert(&mut self, id: u16, commitment: PublicCommitment) {
        self.commitments.insert(id, commitment);
    }
}
