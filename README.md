ENIGMA
=====

Kotlin play ground with PKI


1. How to load private key and cert 
2. How to user PKI to encrypt and decrypt data 


## Generate key and cert

Run the following OpenSSL command to generate your private key and public certificate. Answer the questions and enter the Common Name when prompted.
```bash
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 3650 -out certificate.pem

add -subj "/C=UK/ST=London/L=London/O=bluehex.com/CN=sp.bluehex.com" to avoid questions 

```

Review the created certificate:
```bash

openssl x509 -text -noout -in certificate.pem
```

Combine your key and certificate in a PKCS#12 (P12) bundle:

```bash

openssl pkcs12 -inkey key.pem -in certificate.pem -export -out certificate.p12
```

Validate your P2 file.

```bash

openssl pkcs12 -in certificate.p12 -noout -info
```
