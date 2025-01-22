# Stage 1: Base image
FROM rust:1.81 AS rust
WORKDIR /app

# Install cargo-chef, which will help us utilize Docker's layer caching 
# to speed up builds.
RUN cargo install cargo-chef

# Install dependencies required by compilation later on
RUN apt-get update && apt-get install -yqq build-essential cmake protobuf-compiler


# Stage 2: cargo chef prepare
FROM rust AS planner

# Make cargo-chef analyze project's structure, dependencies, ...
COPY . .
RUN cargo chef prepare --recipe-path recipe.json
 

# Stage 3: Compile
FROM rust AS builder 

# Build dependencies first. This layer can be cached later on.
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Build application itself
COPY . .
RUN cargo build --release --bin server
# Don't strictly speaking need any of these, but we can compile them for cheap 
# as we have a compilation cache available at this point. So we might as well.
RUN cargo build --release --bin client
RUN cargo build --release --bin confgen
RUN cargo build --release --bin thetacli


# Stage 4: Run in plain Debian container
FROM debian:12-slim AS runtime

WORKDIR /app
COPY --from=builder /app/target/release/server /usr/local/bin/
COPY --from=builder /app/target/release/client /usr/local/bin/
COPY --from=builder /app/target/release/confgen /usr/local/bin/
COPY --from=builder /app/target/release/thetacli /usr/local/bin/
COPY log4rs.yaml /app/
COPY log4rs_to_file.yaml /app/

ENTRYPOINT ["/usr/local/bin/server"]
