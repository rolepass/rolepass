FROM rust:alpine AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY schemas/ schemas/
RUN cargo build --release

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/target/release/rolepass /usr/local/bin/rolepass
ENTRYPOINT ["rolepass"]
