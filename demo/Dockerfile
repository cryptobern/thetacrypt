
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
COPY ./thetacrypt_proto $PROJECT_PATH/thetacrypt_proto/

WORKDIR $PROJECT_PATH/threasholdLibrary/protocols

RUN cargo build --release 



FROM debian:buster-slim

RUN apt-get update && apt-get -y install libssl-dev && rm -rf /var/lib/apt/lists/*

#Binaries
COPY --from=builder /rootLibrary/threasholdLibrary/target/release ./target/release 

#Keys
COPY --from=builder /rootLibrary/threasholdLibrary/protocols/conf ./target/release/conf

#Config files
COPY --from=builder /rootLibrary/threasholdLibrary/network/src/config/tendermint_net/config.toml ./target/network/src/config/tendermint_net/
WORKDIR /target/release/

#after docker run you can override CMD 

CMD ["./server", "1"] 
#, "-l"]
