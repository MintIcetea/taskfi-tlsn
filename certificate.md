## How to generate a certificate for Notary Server

1. Generate a certificate request and along with a private key

```
# Use RSA with 2048 bits
openssl req -newkey rsa:2048 -keyout notary.key -out notary.csr
```

2. Generate root certificate

```
# Generate private key of the root CA
openssl genrsa -out rootCA.key 2048

# Generate root CA (10 years)
openssl req -x509 -sha256 -new -nodes -key rootCA.key -days 3650 -out rootCA.crt
```

3. Generate certificate extension

- Not sure what this does, but copy the below into `notary.ext` should work

```
# Certificate extension file content

authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
subjectAltName=hostname
```

4. Generate certificate

```
openssl x509 -req -days 3650 -in notary.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out notary.crt -extfile notary.ext
```

5. Config the notary server to use the generated certificate

- Config template at [TLSN Notary Server](https://github.com/tlsnotary/tlsn/blob/main/notary-server/config/config.yaml)

```
# Use custom generated certificate and key
tls:
  enabled: true
  private-key-pem-path: "./fixture/tls/notary.key"
  certificate-pem-path: "./fixture/tls/notary.crt"
```
