## How to run a demo 

In order to use our library with tendermint we need to run a tendermint testnet. 
In tendermint, the way in which developers can interact with the BFT consensus engine (Tendermint Core) is trough a specific application (ABCI). 
An ABCI app allows to define a replicated state machine code that will be executed on each party and it's the user of our library. 

In order to connect Tendermint Core, the ABCI lib and an instance of our Threshold Library, we provide a docker_compose file, that allows to run everything in a containarized manner. 

In addition, a Makefile with multiple rules is provided so that is straightforward to run all the steps. 

- explain why we need the dir tmp 
- explain how to start the testnet and which are the parameters involved (explain the problem with the RPC server)
- explain why we need the clean-up rule 