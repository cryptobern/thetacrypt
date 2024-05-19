
FROM rust:1.74 as builder 

RUN apt-get update && \ 
    apt-get install -y libssl-dev && \
    apt-get install -y protobuf-compiler && \
    apt-get install -y m4

ENV PROJECT_PATH=/rootLibrary

COPY ./src $PROJECT_PATH/threasholdLibrary

WORKDIR $PROJECT_PATH/threasholdLibrary

RUN cargo build --release 


FROM debian:12

RUN apt-get update && apt-get -y install libssl-dev && rm -rf /var/lib/apt/lists/*
RUN apt-get -y install libc6

#Binaries
COPY --from=builder /rootLibrary/threasholdLibrary/target/release/server /target/release/ 
COPY --from=builder /rootLibrary/threasholdLibrary/target/release/confgen /target/release/ 
COPY --from=builder /rootLibrary/threasholdLibrary/target/release/client /target/release/ 
COPY --from=builder /rootLibrary/threasholdLibrary/target/release/thetacli /target/release/

COPY --from=builder /rootLibrary/threasholdLibrary/log4rs.yaml /target/release/

WORKDIR /target/release/

#after docker run you can override CMD 
CMD ["./server", "--", " --config-file conf/server_0.json", " --key-file conf/keys_0.json"] 

