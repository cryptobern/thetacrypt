# Proposal new protocol design
```
trait ThresholdProtocol{

    //additional methods
    init()

    //current interface 
    do_round()
    is_ready_for_next_round()
    is_finished()
    update()
}
```

The function `run()` that currently is a member function of the trait `ThresholdProtoco` can become a standalone function `run<T: ThresholdProtocol>(protocol: &dyn T)` (&dyn is useful if we need dynamic dispatch, maybe we don't). In this way the execution layer can have less code and just pass a struct that implements the trait.

With the current protocols that we have right now, we should then have three structs that implement the trait: namely `ThresholdCipher`, `ThresholdSignature`, `ThresholdRandomness`.

We can have a concrete type that has the all the common properties to manage the execution:
```
ThresholdProtocolInstance<P: ThresholdProtocol>{
 private_key: Arc<PrivateKeyShare>,
 chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
 chan_out: tokio::sync::mpsc::Sender<NetMessage>,
 instance_id: String,
 valid_shares: Vec<DecryptionShare>, //to see if we can have a general comcept of sheres or this should be maintained in the ProtocolType
 event_emitter_sender: tokio::sync::mpsc::Sender<Event>,
 protocol: P,
}
```
In implementing the `ThresholdProtocol` trait, each protocol can define the behaviour of the interface.

//Let's try to write the interface for the Cipher
```
pub struct ThresholdCipherProtocol {
    private_key: Arc<PrivateKeyShare>, //The information about the scheme-group is in the Key
    ciphertext: Ciphertext,
    valid_shares: Vec<DecryptionShare>,
    decrypted: bool,
    decrypted_plaintext: Vec<u8>, //result
    received_share_ids: HashSet<u16>,
    

    //added params
    state: ProtocolState //define the behaviour of the round
}

enum CipherProtocolState{
    Init
    DecryptionShare
    Terminated
}

//the type ThresholdCipher is an interface type exposed by the schemes module and provides the primitives for the protocol

impl ThresholdProtocol for ThresholdCipherProtocol {
    fn init(){
        //init ProtocolState
    }
    fn do_round() -> RoundResult {
        //switch on the value of ProtocolState -- here there is just one
            //verify ciphertext
            //create share 
            let share =
            ThresholdCipher::partial_decrypt(&self.ciphertext, &self.private_key, &mut params)?;
            //wrap in the RoundResult the share
            return
    }

    fn update(RoundResult) {
        //unwrap RoundResult
        //updates local variables
        //check the condition for chanching the state
            //update states: here will be to produce the result
    }

    fn is_finished(RoundResult) -> ProtocolResult {
        return self.result //produced in the 
    }

    fn is_ready_for_next_round() -> bool {
        //check the condition for a specific state
        if valid_shares.len() > threshold {
            return true
        }
        return false
    }
}

//The issue is to understand how the interface should work with the ThresholdSignatureProtocol if it has more rounds: 
```

approaches: 

- pass to the interface a tuple of (round, operation)
- have more protocols interfaces that let compose primitives (e.g., in the case of FROST we have ThresholdInteractiveScheme that composes, ThresholdPrecomputations and ThresholdSignature primitives)



What I don't like right now is that the logic between the primitives and the protocol is mixed.

Open questions: 
- At which level we should find the information on the number of rounds? 
- How many layers of interfaces there should be?
Now from the API level we give an indication of which scheme to use with the tuple scheme and group, later at the protocol layer we fetch the key, and in the interface we the schemes layer we use the key to infer the precise scheme to use.