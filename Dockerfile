FROM rust:alpine AS builder
WORKDIR /build

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release && rm -rf src

COPY src/ src/
COPY schemas/ schemas/
RUN touch src/main.rs && cargo build --release

FROM alpine:latest
RUN apk add --no-cache ca-certificates && adduser -D -h /home/rolepass rolepass
USER rolepass
COPY --from=builder /build/target/release/rolepass /usr/local/bin/rolepass
ENTRYPOINT ["rolepass"]
