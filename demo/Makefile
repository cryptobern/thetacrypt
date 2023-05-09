
## TODO: 
## 1. change names to the tendermint node (currently node0 ...)
## 2. See if in the generation of the config file we can pass the ip for RPC server (it has to be 0.0.0.0)
## 3. See if is it possible to pass the IP as a parameter or read it from the env file in the Makefile 
## 4. Make a rule for cleaning the environment at the stop and recreate everything (depends on 2.)

## How to run 
# 1	# create a tmp directory to be the shared memory between your computer and docker
# 	# if you encounter this error
# 	# -- Could not create directory /tendermint/config. mkdir /tendermint/config: permission denied
# 	# you need to give docker the permission to write in that location 
# 	# run -> chmod 777 tmp


set-up:
	@if ! [ -d tmp ]; then mkdir tmp; fi
	@chmod -R 777 tmp
	@cp config-template.toml tmp/config-template.toml
	@if ! [ -d config ]; then mkdir config; fi
	@chmod -R 777 config
	@cp server_ips.txt config/server_ips.txt
	@cp tendermint_ips.txt config/tendermint_ips.txt
.PHONY: set-up

build-docker:
	docker build -t rust-threshold-library -f Dockerfile .. 
	docker build -t abci-img -f Dokerfile.abci .
.PHONY: build-docker

cross-compile-linux:
	@rustup target add x86_64-unknown-linux-gnu
	@brew install SergioBenitez/osxct/x86_64-unknown-linux-gnu
.PHONY: build-linux

build-binary-thetacrypt:
	@cargo build --release --target=x86_64-unknown-linux-gnu --manifest-path=../src/Cargo.toml
.PHONY: build-binary

build-binary-abci:
	@x86_64-unknown-linux-gnu cargo build --release --target x86_64-unknown-linux-gnu --manifest-path ./abci_app/Cargo.toml
.PHONY: build-binary

build-docker-test: build-binary-thetacrypt build-binary-abci
	docker build -t rust-threshold-library-test -f Dockerfile.test .. 
	docker build -t abci-img-test -f Dockerfile.abci.test .
.PHONY: build-docker-test

# Distinguish a setup between the demo with the custom network and the demo with tendermint p2p
config-files: #set-up
	@if ! [ -f ./config/server_0.json ]; then docker run --rm -v $(CURDIR)/config:/target/release/conf:Z rust-threshold-library ./confgen --ip-file=conf/server_ips.txt --outdir=conf -i --integration-file=conf/tendermint_ips.txt ; fi
	@if ! [ -f ./config/keys_0.json ]; then docker run --rm -v $(CURDIR)/config:/target/release/conf:Z rust-threshold-library ./trusted_dealer 3 4; fi
	@if ! [ -f ./tmp/node0/config/genesis.json ]; then docker run --rm -v $(CURDIR)/tmp:/tendermint:Z tendermint/localnode:latest testnet --config config-template.toml --o . --starting-ip-address 192.167.20.10; fi
.PHONY: config-files

config-files-test: #set-up
	@if ! [ -f ./conf/keys_0.json ]; then docker run --rm -v $(CURDIR)/config:/target/release/conf:Z rust-threshold-library-test ./trusted_dealer 3 4; fi
	@if ! [ -f ./conf/server_0.json ]; then docker run --rm -v $(CURDIR)/config:/target/release/conf:Z rust-threshold-library-test ./confgen --ip-file=conf/server_ips.txt --outdir=conf -i --integration-file=conf/tendermint_ips.txt ; fi
	@if ! [ -f ./tmp/node0/config/genesis.json ]; then docker run --rm -v $(CURDIR)/tmp:/tendermint:Z tendermint/localnode:latest testnet --config config-template.toml --o . --starting-ip-address 192.167.20.10; fi
.PHONY: config-files-test

demo-start-test: config-files-test copy-nodes
	docker compose up -f docker-compose-test.yml
.PHONY: demo-start-test

demo-start: #config-files
	docker-compose up
.PHONY: demo-start

demo-stop:
	docker-compose down
.PHONY: demo-stop

clean-up: demo-stop
	@rm -r tmp
	@rm -r config
.PHONY: clean-up

# Test rules 

clean-nodes: 
	rm -r tmp/node0
	rm -r tmp/node1
	rm -r tmp/node2
	rm -r tmp/node3
.PHONY:  ckean-nodes

copy-nodes: 
	cp -R node0 tmp/
	cp -R node1 tmp/
	cp -R node2 tmp/
	cp -R node3 tmp/
.PHONY: copy-nodes



