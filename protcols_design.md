# Proposal new protocol design
```
trait ThresholdProtocol{

    //additional methods
    init() //initialize the state of the variables (maybe it doesn't need to be in the trait)

    //current interface 
    do_round()
    is_ready_for_next_round()
    is_finished()
    update()
    terminate() //Executor
}
```

The function `run()` that currently is a member function of the trait `ThresholdProtocol` can become a standalone function `execute_protocol<T: ThresholdProtocol>(protocol: &dyn T)` (&dyn is useful if we need dynamic dispatch, maybe we don't). Alternatively can be a member method of `ThresholdProtocolInstance`.

We can rename `ThresholdProtocolInstance` as `ThresholdProtocolExecutor`.

In this way the execution layer can have less code and just pass a struct that implements the trait, or have a delegate object on which to call the specific function. (See the parameter P)

With the current protocols that we have right now, we should then have four structs that implement the trait: namely `ThresholdCipher`, `ThresholdSignature`, `ThresholdRandomness`, `FROST`.

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

## Considerations on the update() function, RoundResult and managing messages

**Every protocol should implement a message_handler Trait for process correctly protocol specific messages. To consider is that in a certain state, or round we could receive a message from other rounds. This depends on the progress of the protocol in other nodes.**

In the update function we should consider that we can receive a RoundResult (or in general a message that is not from that round). In the update() function for FROST the logic is currently well handled because based on the message we update two different vectors that are then used to check termination conditions of the rounds. To explore how this should work for more complex protocols like DKG.

For now we can observe that the update function is the one in which we should handle different messages. The protocol can have a process_message() function. The function can be part of the ThresholdProtocol trait, or a new trait ThresholdProtocolMessageHandler. 

Maybe we need to rethink messages and RoundResult. It can be the case that in a round one has different types of message to send around. We cannot have a 1:1 mapping. Change the enum doesn't need to be called RoundOne and RoundTwo. 

## Handling multi-round protocols

**What I don't like right now is that the logic between the primitives and the protocol is mixed.**

I would distinguish at the protocol level between FROST and SH00 and BLS04. We can claim that from a protocol point of view, SH00 and BLS04 scheme share the same protocol, while FROST defines a new one. So it is ok to have two different implementations.  

Open questions:

- At which level we should find the information on the number of rounds? At the protocol level, high level information.

Observation:
Now from the API level we give an indication of which scheme to use with the tuple scheme and group, later at the protocol layer we fetch the key, and in the interface we the schemes layer we use the key to infer the precise scheme to use.
