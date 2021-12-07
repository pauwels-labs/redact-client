FROM rust:1.57.0-alpine3.13 AS builder

# Create an unprivileged user
RUN adduser --disabled-password --no-create-home --uid 1000 notroot notroot

# Perform apk actions as root
RUN apk add --no-cache musl-dev=1.2.2-r1 openssl-dev=1.1.1l-r0 libsodium-dev=1.0.18-r0 make=4.3-r0

# Create build directory as root
WORKDIR /usr/src
RUN USER=root cargo new redact-client

# Perform an initial compilation to cache dependencies
WORKDIR /usr/src/redact-client
COPY Cargo.lock Cargo.toml ./
RUN echo "fn main() {println!(\"if you see this, the image build failed and kept the depency-caching entrypoint. check your dockerfile and image build logs.\")}" > src/main.rs
RUN cargo build --release --locked

# Load source code to create final binary
RUN rm -rf src
RUN rm -rf target/release/deps/redact_client*
RUN rm -rf target/release/redact-client*
COPY src src
RUN cargo build --release --locked

# Create tiny final image containing binary
FROM scratch

# Load unprivileged user from build container
COPY --from=builder /etc/group /etc/passwd /etc/

# Switch to unprivileged user
USER notroot:notroot

# Copy binary files
WORKDIR /usr/local/bin
COPY --from=builder /usr/src/redact-client/target/release/redact-client service

ENTRYPOINT ["service"]
