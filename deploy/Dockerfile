# Cairn container image (skeleton). Build: docker build -f deploy/Dockerfile .
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p cairn-cli --locked

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/cairn /usr/local/bin/cairn
VOLUME ["/data"]
EXPOSE 9000
ENV CAIRN_DATA_DIR=/data CAIRN_SERVER_LISTEN=0.0.0.0:9000
ENTRYPOINT ["/usr/local/bin/cairn"]
CMD ["serve"]
