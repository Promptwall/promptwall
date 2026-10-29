# Promptwall proxy and the mock provider used for demos and benchmarks.
#   docker build -t promptwall .
FROM rust:1.90-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p promptwall -p pw-mock-upstream

FROM debian:bookworm-slim
# TLS roots are built into the binary (webpki-roots), so no CA package is needed.
RUN useradd --system --uid 10001 promptwall
COPY --from=build /src/target/release/promptwall /src/target/release/pw-mock-upstream /usr/local/bin/
USER promptwall
ENV PROMPTWALL_LISTEN=0.0.0.0:8080
EXPOSE 8080 9464
ENTRYPOINT ["promptwall"]
