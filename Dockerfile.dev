FROM docker.io/ubuntu:24.04 AS builder

RUN apt update && apt upgrade -y
RUN apt install -y gcc curl

WORKDIR /tmp/
RUN curl -o rustup.sh --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs
RUN chmod +x /tmp/rustup.sh && /tmp/rustup.sh -y --default-toolchain stable-x86_64-unknown-linux-gnu

WORKDIR /app/
COPY . .
RUN . "$HOME/.cargo/env" && cargo build

FROM docker.io/ubuntu:24.04

WORKDIR /app/
COPY --from=builder /app/target/debug/pass-wall /app/
COPY ./static/ /app/static/

ENTRYPOINT ["/app/pass-wall"]

