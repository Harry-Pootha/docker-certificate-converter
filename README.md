# docker-openssl-converter
A container to convert certificates to different types (e.g. pfx file to key and pem)
---

This container scans the directory mounted at `/openssl-certs` continously.
When finding a .pfx file it uses openssl commands to convert the certificate to pem.
The passphrase of the .pfx can be passed using the environment variable `CERT_PASSPHRASE`
This also exports the key and removes any passphrase.

The certificate and key file will be named the same as the .pfx file.
The file extensions will be filename.key and filename.crt.
The original .pfx file is renamed to filename.pfx.converted

### Example docker-compose.yml:

```
name: openssl-converter

services:
  openssl-converter:
    container_name: openssl-converter
    image: harrypootha/certificate-converter:latest
    environment:
      - CERT_PASSPHRASE=PLACEHOLDER
      - GENERATE=false
    volumes:
      - ./examples/:/openssl-certs
```