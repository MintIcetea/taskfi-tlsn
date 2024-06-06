# Build binary from source
FROM rust:1.77.2 AS build
WORKDIR /app

COPY . .

RUN cargo build --release

# Smaller runtime
FROM debian:bookworm-slim AS runtime
WORKDIR /app

# Install openssl - it's dynamically linked by some of our dependencies
# Install ca-certificates - it's needed to verify TLS certificates when establishing HTTPS connections
RUN apt-get update \
  && apt-get install openssl -y \
  && apt-get install ca-certificates -y \
  && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/target/release/taskfi-tlsn taskfi-tlsn

# Copy over server configuration
COPY config/base.json config/base.json
COPY config/production.json config/production.json

ENV APP_ENV production
ENV RUST_LOG info
ENTRYPOINT [ "./taskfi-tlsn" ]