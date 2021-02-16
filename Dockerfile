FROM rust:alpine3.12 AS builder

# Create an unprivileged user
RUN adduser --disabled-password --no-create-home --uid 1000 notroot notroot

# Perform apk actions as root
RUN apk add --no-cache musl-dev

# Create build directory as root
WORKDIR /usr/src
RUN USER=root cargo new service

# Perform an initial compilation to cache dependencies
WORKDIR /usr/src/service
COPY Cargo.lock Cargo.toml ./
RUN echo "fn main() {println!(\"if you see this, the image build failed and kept the depency-caching entrypoint. check your dockerfile and image build logs.\")}" > src/main.rs
RUN cargo build --release

# Load source code to create final binary
RUN rm -rf src
RUN rm -rf target/release/deps/service*
COPY src src
RUN cargo build --release

# Create tiny final image containing binary
FROM scratch

# Load unprivileged user from build container
COPY --from=builder /etc/group /etc/passwd /etc/

# Switch to unprivileged user
USER notroot:notroot

# Copy binary files
WORKDIR /usr/local/bin
COPY --from=builder /usr/src/service/target/release/redact-client service

ENTRYPOINT ["service"]
