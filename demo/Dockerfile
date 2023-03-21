
FROM rust as builder 
# :alpine

# RUN apk update && \
#     apk upgrade && \
#     apk --no-cache add curl jq file && \
#     apk add --update alpine-sdk && \
#     apk --no-cache add libressl-dev && \
#     apk --no-cache add protoc && \
#     apk add m4

RUN apt-get update && \ 
    apt-get install libssl-dev && \
    apt install -y protobuf-compiler && \
    apt-get install m4

# ENV OPENSSL_STATIC=true

# ENV RUSTFLAGS='-C target-feature=+crt-static'

# RUN apk add libc-dev openssl-dev gdb strace && apk update

ENV PROJECT_PATH=/rootLibrary

COPY ./src $PROJECT_PATH/threasholdLibrary

WORKDIR $PROJECT_PATH/threasholdLibrary/protocols

#just to fix the issue with the snow dependency
#RUN cargo update -p curve25519-dalek@4.0.0-rc.0 --precise 4.0.0-pre.5 

RUN cargo build --release 



FROM debian:bullseye

RUN apt-get update && apt-get -y install libssl-dev && rm -rf /var/lib/apt/lists/*

#Binaries
COPY --from=builder /rootLibrary/threasholdLibrary/target/release/server /target/release/ 
COPY --from=builder /rootLibrary/threasholdLibrary/target/release/confgen /target/release/ 
COPY --from=builder /rootLibrary/threasholdLibrary/target/release/client_app /target/release/ 
COPY --from=builder /rootLibrary/threasholdLibrary/target/release/trusted_dealer /target/release/ 

#Config files (to remove eventually)
COPY --from=builder /rootLibrary/threasholdLibrary/network/src/config/tendermint_net/config.toml ./target/network/src/config/tendermint_net/
WORKDIR /target/release/

#after docker run you can override CMD 

CMD ["./server", "--", " --config-file conf/server_0.json", " --key-file conf/keys_0.json"] 

