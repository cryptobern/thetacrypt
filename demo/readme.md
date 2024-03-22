# Demo application 

## Introduction 

The demo application aims at showcasing the usage of Thetacrypt in a distributed deployment. Thetacrypt has been designed with two system configurations in mind. The first one entails the use of Thetacrypt as a standalone distributed service and requires the development of an application that wants to use it. The second configuration is the integration with a blockchain platform. In this case, an instance of Thetacrypt will run on each validator node of a blockchain and the service can be called from a smart contract upon the delivery of a consensus decision.

To make it simpler to run and try out our service we provide a demo application with Docker. In this way to run the demo you just need docker installed on your machine.

## Local configuration

A `Makefile` provides a step-by-step guide to learning about our software.

The Makefile presents the following rules:

- *set-up*: it creates a temporary directory, `tmp`. `tmp` will be a shared volume between the host and the containers running a Thetacrypt image and will allow the users to read the generated initial config files needed by the nodes of the network.  <br>
<br> The `tmp` directory at the end of this first step will contain a text file, `server_ips.txt`, containing the list of IPs of our library nodes.  <br>

- *build-docker*: builds the library docker image, `rust-threshold-library`, needed for subsequent steps.

- *config-files*: generates configuration files for every Thetacrypt instance. While the script `confgen` is used to provide the network information of each instance, the script `Thetacli` with the parameter `keygen` is used to generate the key shares for each of them. All the resulting files will be placed in the shared volume `tmp`, mapped to the `conf` directory under `src/protocol` in the root directory.  To read more about these scripts you can refer to the library documentation.

- *demo-start*: calls the `docker-compose.yml` file to build a network of four Thetacrypt nodes.

- *demo-stop*: performs just a command to stop all the running containers built from the `docker-compose.yml`.

- *client-start*: provides the right docker instruction to run a client script that connects to all the servers.

- *clean-up*: removes the `tmp` directory.

### How to run the demo 

1) Clone the directory <br> 
```
git clone <GitHub Link>
cd <GitHub Repo>/demo
```
2) Run the necessary rules to prepare the environment and start the network of nodes inside docker <br>
```
make set-up
make build-docker
make config-files
make demo-start
```
3) The last step will allow you to run a client app that starts the interaction with every thetacrypt node in the network. Open another terminal window and type: 
```
make client-start
```

In this way, you make use of the image of the library already built and run everything inside the docker network defined in the `docker-compose.yml`.

Alternatively, you can run the client script on your host:

```
cd ../src/protocols
cargo run --bin client -- --config-file=../../demo/tmp/client.json
```

Be aware that in this case, you need the toolchain and all the dependencies to run a Rust program.  
