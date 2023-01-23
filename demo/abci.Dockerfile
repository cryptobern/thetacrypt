
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

ENV PROJECT_PATH=/img_root

COPY ./thetacrypt_proto $PROJECT_PATH/thetacrypt_proto/
COPY ./demo/abci_app $PROJECT_PATH/demo/abci_app/

WORKDIR $PROJECT_PATH/demo/abci_app

RUN cargo install --path $PROJECT_PATH/demo/abci_app

#after docker run you can override CMD 

CMD ["fair_order_app", "--tcl-port=50051"] 
