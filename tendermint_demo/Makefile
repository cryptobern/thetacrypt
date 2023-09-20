
## TODO: 
## 1. change names to the tendermint node (currently node0 ...)
## 2. See if in the generation of the config file we can pass the ip for RPC server (it has to be 0.0.0.0)
## 3. See if is it possible to pass the IP as a parameter or read it from the env file in the Makefile 
## 4. Make a rule for cleaning the environment at the stop and recreate everything (depends on 2.)

## How to run 
# 1	# create a tendermint directory to be the shared memory between your computer and docker
# 	# if you encounter this error
# 	# -- Could not create directory /tendermint/config. mkdir /tendermint/config: permission denied
# 	# you need to give docker the permission to write in that location 
# 	# run -> chmod 777 tendermint


set-up:
	@if ! [ -d tendermint ]; then mkdir tendermint; fi
	@chmod -R 777 tendermint
	@cp config-template.toml tendermint/config-template.toml
	@if ! [ -d config ]; then mkdir config; fi
	@chmod -R 777 config
	@cp server_ips.txt config/server_ips.txt
	@cp tendermint_ips.txt config/tendermint_ips.txt
.PHONY: set-up

build-docker:
	DOCKER_BUILDKIT=1 docker build -t rust-threshold-library -f Dockerfile .. 
	DOCKER_BUILDKIT=1 docker build -t abci-img -f abci.Dockerfile ..
	DOCKER_BUILDKIT=1 docker build -t tendermint/thetacrypt -f tendermint.Dockerfile .
.PHONY: build-docker

# Distinguish a setup between the demo with the custom network and the demo with tendermint p2p
config-files-integration: #set-up
	@if ! [ -f ./config/server_0.json ]; then docker run --rm -v $(CURDIR)/config:/target/release/conf:Z rust-threshold-library ./confgen --ip-file=conf/server_ips.txt --outdir=conf -i --integration-file=conf/tendermint_ips.txt ; fi
	@if ! [ -f ./config/keys_0.json ]; then docker run --rm -v $(CURDIR)/config:/target/release/conf:Z rust-threshold-library ./trusted_dealer 3 4; fi
	@if ! [ -f ./tendermint/node0/config/genesis.json ]; then docker run --rm -v $(CURDIR)/tendermint:/tendermint:Z tendermint/thetacrypt testnet --config config-template.toml --o . --starting-ip-address 192.167.20.10 --config-thetacrypt-service true --starting-ip-address-thetacrypt 192.167.20.2; fi
.PHONY: config-files

config-files: #set-up
	@if ! [ -f ./conf/keys_0.json ]; then docker run --rm -v $(CURDIR)/config:/target/release/conf:Z rust-threshold-library-test ./trusted_dealer 3 4; fi
	@if ! [ -f ./conf/server_0.json ]; then docker run --rm -v $(CURDIR)/config:/target/release/conf:Z rust-threshold-library-test ./confgen --ip-file=conf/server_ips.txt --outdir=conf; fi
	@if ! [ -f ./tendermint/node0/config/genesis.json ]; then docker run --rm -v $(CURDIR)/tendermint:/tendermint:Z tendermint/localnode:latest testnet --config config-template.toml --o . --starting-ip-address 192.167.20.10; fi
.PHONY: config-files-test

demo-start: #config-files
	docker-compose up
.PHONY: demo-start

demo-stop:
	docker-compose down
.PHONY: demo-stop

clean-up: demo-stop
	@rm -r tendermint
	@rm -r config
.PHONY: clean-up




