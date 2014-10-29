# Cryptaes

Python AES encryption/decryption program.

## Usage
```
cryptaes [-h] (--encrypt | --decrypt) --output OUTPUT
                [--iv IV | --ivfile IVFILE]
                [--key SECRET | --keyfile SECRETFILE] [--mode MODE] [--info]
                file
```

### Arguments:
  - **file**                  The file for encrypt or decrypt
  - (**--encrypt|--decrypt**) Encrypt or decrypt message

### Optional arguments:
  - **--output OUTPUT**       Output file
  - **--iv IV**               IV
  - **--ivfile IVFILE**       Input IV file
  - **--key SECRET**          Secret key
  - **--keyfile SECRETFILE**  Input secret key file
  - **--mode MODE**           Operation mode OFB, ECB, CTR, CBC, GCM, CFB, CFB8
                        [default: CBC]
