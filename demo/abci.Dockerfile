
FROM rust
#:alpine

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

ENV PROJECT_PATH=/threasholdLibrary

COPY ./src $PROJECT_PATH

RUN cargo install --path $PROJECT_PATH/abci_app

WORKDIR $PROJECT_PATH/abci_app

#after docker run you can override CMD 

CMD ["fair_order_app", "--tcl-port=50051"] 
