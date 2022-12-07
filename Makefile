
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
.PHONY: set-up

testnet-start: set-up
	@if ! [ -f ./tmp/node0/config/genesis.json ]; then docker run --rm -v $(CURDIR)/tmp:/tendermint:Z tendermint/tendermint:v0.34.20 testnet --config config-template.toml --o . --starting-ip-address 192.167.20.10; fi
	docker-compose up
.PHONY: testnet-start

testnet-stop:
	docker-compose down
.PHONY: testnet-stop

clean-up:
	@rm -r tmp
.PHONY: clean-up

