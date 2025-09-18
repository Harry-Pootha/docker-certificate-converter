FROM alpine:latest

# Install OpenSSL
RUN apk update && \
  apk add --no-cache openssl && \
  rm -rf "/var/cache/apk/*"

ENV CERT_PASSPHRASE ""
ENV GENERATE "false"

COPY run.sh /docker/run.sh

# Create and set mount volume
WORKDIR /openssl-certs

ENTRYPOINT ["sh", "/docker/run.sh"]