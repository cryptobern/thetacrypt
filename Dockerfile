
FROM rust:alpine

RUN apk update && \
    apk upgrade && \
    apk --no-cache add curl jq file && \
    apk add --update alpine-sdk && \
    apk --no-cache add libressl-dev && \
    apk --no-cache add protoc && \
    apk add m4

ENV PROJECT_PATH=/threasholdLibrary

COPY ./src $PROJECT_PATH

RUN cargo install --path $PROJECT_PATH/protocols

WORKDIR $PROJECT_PATH/protocols

#after docker run you can override CMD 

CMD ["server", "1"] 
#, "-l"]
