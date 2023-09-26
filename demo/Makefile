set-up:
	@if ! [ -d tmp ]; then mkdir tmp; fi
	@chmod -R 777 tmp
	@cp server_ips.txt tmp/server_ips.txt
.PHONY: set-up

build-docker:
	docker build -t rust-threshold-library -f Dockerfile .. 
.PHONY: build-docker

config-files: 
	@if ! [ -f ./conf/keys_0.json ]; then docker run --rm -v $(CURDIR)/tmp:/target/release/conf:Z rust-threshold-library ./thetacli keygen 3 4 sg02-bls12381 ./conf; fi
	@if ! [ -f ./conf/server_0.json ]; then docker run --rm -v $(CURDIR)/tmp:/target/release/conf:Z rust-threshold-library ./confgen --ip-file=conf/server_ips.txt --outdir=conf; fi # the outdir here is created under protocols
.PHONY: config-files

demo-start: config-files
	docker-compose up
.PHONY: demo-start

client-start: 
	docker run -it -v $(CURDIR)/tmp:/target/release/conf:Z --net threshold-net rust-threshold-library ./client --config-file=conf/client.json
.PHONY: client-start

demo-stop:
	docker-compose down
.PHONY: demo-stop

clean-up: demo-stop
	@rm -r tmp
.PHONY: clean-up




