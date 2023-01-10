# Demo application 

## Introduction 

The demo application aims to show how in a blockchain platform, upon receiving an encrypted message, the nodes of the distributed system want to 
colaborate in order to decrypt a message using **Threshold Cryptography**. 

We integrated the library with the open source blockchain platform, Tendermint. 

In order to set up a network of tendermint nodes, we need to run a tendermint testnet. 
In tendermint, the way in which developers can interact with the BFT consensus engine (Tendermint Core) is trough a specific application (ABCI). 
An ABCI app allows to define a replicated state machine code that will be executed on each party and, in our demo, this module is the user of our library. 

In order to connect Tendermint Core, the ABCI app and an instance of our Threshold Library, we provide a 'docker_compose' file, that allows to run everything in a containarized manner. 

In addition, a Makefile with multiple rules is provided so that is straightforward execute all the necessary steps. 

In the Makefile there are four rules: 

- *set-up*: it creates a temporary directory, `tmp`. `tmp` will be a shared volume between the host and the containers running a tendermint image, and will allow the users to read (possibly modify) the genesis file and initial config files needed by the nodes of the network.

- *testnet-start* : it sets up the necessary file to run a network of tendermint nodes using a special script provided by tendermint itself, `testnet`. This script allows to configure a tendermint network with a certain number of nodes, generates the necessary config files, and, throught several options, allows an extensive degree of liberty in defining numbers of validator, ips, and other setting options. 

It is worth mentioning that we use a pre-built image of tendermint from Docker Hub with a specific version of the codebase, *v0.34.20*. This choice is related to the use of the Rust Tendermint API, `rs-tendermint`, in the development of the ABCI app.  

Finally, the rule calls the docker compose file to build a network of four tendermint nodes, four ABCI apps to which tendermint nodes need to connect to, and four nodes running our library (to which the ABCI apps connect to).   

- testnet-stop: it performs just a command to stop all the running containers built from the compose file. 
- clean-up: it removes the `tmp` directory. 

## How to run the demo 

1) Clone the directory 
```
git clone <DIR>
cd 2021.cosmoscrypto/demo
```
2) 
```
make set-up
make testnet-start
```
3) The last step will allow you to run a client app that starts the interaction with the blockchain and triggers the decryption protocol implementend by our library. Open another terminal window and type: 
```
docker run -it --network=threshold-net rust-threshold-library client_app --tendermint-node-ip 192.167.20.10
```

In this way you make use of the image of the library already built and run everything inside the docker network defined in the compose file. 

Alternatively, you can run the client script on your host: 
```
cd ../src/protocols/src/bin
cargo run --bin client_app
```

Be aware that in this case you need the toolchain and all the dependencies to run a rust program.  


  
<!-- - explain why we need the dir tmp 
- explain how to start the testnet and which are the parameters involved (explain the problem with the RPC server)
- explain why we need the clean-up rule  -->
