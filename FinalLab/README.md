# Encryptator

## Install requirements
```
user@machine$ easy_install cryptography==0.7.1
user@machine$ easy_install ecdsa==0.11
user@machine$ easy_install pycrypto==2.6.1
```

## Usage


### Send message
sage: encryptator.py send [-h] message signatureKey publicKey

Send encrypted message

positional arguments:
  message       file to encrypt
  signatureKey  file containing the private key signature of signatory
  publicKey     file containing the public key of the receiver of the message

optional arguments:
  -h, --help    show this help message and exit


### Recieve message
usage: encryptator.py receive [-h] message verificaitonKey privateKey

Receive encrypted message

positional arguments:
  message          file to decrypt
  verificaitonKey  file containing the public key to verify the signature
                   signing
  privateKey       file containing the private key to decrypt the message

optional arguments:
  -h, --help       show this help message and exit


### Generate ECC Keys
usage: encryptator.py ecc [-h] {NIST192p,NIST224p,NIST256p,NIST384p,NIST521p}

Generate ECC key

positional arguments:
  {NIST192p,NIST224p,NIST256p,NIST384p,NIST521p}
                        curve name

optional arguments:
  -h, --help            show this help message and exit


### Generate RSA Keys
usage: encryptator.py rsa [-h] {1024,2048,3072,4096}

Generate RSA key

positional arguments:
  {1024,2048,3072,4096}
                        key length in bits

optional arguments:
  -h, --help            show this help message and exit


### Sign file
usage: encryptator.py sign [-h] file signatureKey

Sign file

positional arguments:
  file          file to sign
  signatureKey  file containing the private key signature of signatory

optional arguments:
  -h, --help    show this help message and exit


### Verify signature
usage: encryptator.py verify [-h] file signature verificaitonKey

Sign file

positional arguments:
  file             file to verify
  signature        file with signature to verify
  verificaitonKey  file containing the key for verify the signature

optional arguments:
  -h, --help       show this help message and exit


### Encrypt file
usage: encryptator.py encrypt [-h] file key

Encrypt file

positional arguments:
  file        file to encrypt
  key         file with secret key for encrypt

optional arguments:
  -h, --help  show this help message and exit


### Decrypt file
usage: encryptator.py decrypt [-h] file key

Decrypt file

positional arguments:
  file        file to decrypt
  key         file with secret key for decrypt

optional arguments:
  -h, --help  show this help message and exit