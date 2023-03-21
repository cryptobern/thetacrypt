
FROM rust as builder

RUN apt-get update && \ 
    apt-get install libssl-dev && \
    apt install -y protobuf-compiler && \
    apt-get install m4

ENV PROJECT_PATH=/img_root

COPY ./src/proto $PROJECT_PATH/src/proto/
COPY ./demo/abci_app $PROJECT_PATH/demo/abci_app/

RUN cargo install --path $PROJECT_PATH/demo/abci_app


FROM debian:buster-slim

RUN apt-get update && apt-get -y install libssl-dev && rm -rf /var/lib/apt/lists/*

#Binaries
COPY --from=builder /img_root/demo/abci_app/target/release ./target/release 

WORKDIR /target/release

#after docker run you can override CMD 

CMD ["./fair_order_app", "--tcl-port=50051"] 
