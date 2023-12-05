# Blockchain Stub

This module aims to provide the abstraction of a blockchain platform, exposing the intended interface to Thetacrypt.

In its integration mode, Thetacrypt relies on two proxy modules to communicate with the blockchain: a P2PProxy and a TOBProxy.
At the current stage, both behaviors are merged into the same module proxy in the network package.

The important thing to know is that, when in integration mode, Thetacrypt can forward a message in the network assuming access to a start p2p network,
or to a total order broadcast channel that ensures and enforces that every party (server) in the network will receive messages in the same order.

Firstly, the blockchain stub implements the interface that a target platform into which Thetacrypt can be integrated needs to implement.
Secondly, gives an easy way to test the integration communication and the logic of protocols that need TOB.

## How to run Theatacrypt in integration mode

The following guide mirrors the steps of the main one under `<root>/src` to run a simple network of $4$ Thetacrypt nodes, a client, plus an instance of a blockchain stub.

### Generating server configuration

The steps to generate the configuration files are the following, assuming `../src` as cwd, and that one wants a local deployment.

1. Create two files with the IP addresses of the servers, and of the proxies. For example you can use:

```
cat > conf/server_ips << EOF
127.0.0.1
127.0.0.1
127.0.0.1
127.0.0.1
EOF
```

and

```
cat > conf/proxy_ips << EOF
127.0.0.1
127.0.0.1
127.0.0.1
127.0.0.1
EOF
```

Here the proxy IPs are all localhost (or all the same) because we are using the stub, otherwise, here we will have a list of the IPs of different blockchain nodes, to which every thetacrypt instance needs to connect.

2. Generate configuration files:

```
cargo run --bin confgen -- --ip-file conf/server_ips.txt --port-strategy consecutive --outdir=conf -i --integration-file conf/proxy_ips.txt --stub
```

The option `--port-strategy` can be `static` or `consecutive`. The first uses the same port for each IP (suited for a distributed deployment), and the latter assigns incremental values of the port to the IPs (suited for a local deployment).

The two options `-i` and `--integration-file` are used to generate different configuration files for the server that in this mode do not need the information about every other node in the network.

The binary `confgen` generates an extra config file, `client.json`, that has a list of the servers' public information: ID, IP, and rpc_port. This information can be used by a client script to call Thetacrypt's services on each node.

The option `--stub` will create an extra config file `stub.json`, that has a list of the servers' p2p information.


3. Generate the keys for each server.

This step is the same as in the local deployment.


### Starting the server binary

The server is implemented in `bin` and can be started using `src\bin\proxy_server.rs`.
From the root directory of the `src` project start 4 terminals and run, respectively:
```
cargo run --bin proxy_server -- --config-file conf/server_0.json --key-file conf/keys_0.json
cargo run --bin proxy_server -- --config-file conf/server_1.json --key-file conf/keys_1.json
cargo run --bin proxy_server -- --config-file conf/server_2.json --key-file conf/keys_2.json
cargo run --bin proxy_server -- --config-file conf/server_3.json --key-file conf/keys_3.json
```

The server prints info messages, to see them set the following environment variable: `RUST_LOG=info`
(or see here for more possibilities: https://docs.rs/env_logger/latest/env_logger/).

You should see each server process print that it is connected to the others and ready to receive client requests.

**The server can also be run without specifying the `--key-file` flag, this is optional.** In the future, the service will support algorithms to generate the key(DKG) or compute randomness in a distributed manner without any previous setup.

## Run an example client

An RPC client, meant only to be used as an example, can be found in `\src\bin\client.rs`. To run this client, open a new terminal and run:
```
cargo run --bin client -- --config-file=conf/client.json
```
The client presents a menu of options for experimenting with the different schemes provided by the service. For example, in the case of a decryption operation, it creates a ciphertext and then submits a decryption request to each server using the `decrypt()` RPC endpoints.
The code waits for the key **Enter** to be pressed before submitting each request.

## Run an example stub

To run the blockchain stub, 

```
cd thetacrypt_blockchain_stub
```

and run: 

```
cargo run --bin server -- --config-file ../conf/stub.json
```