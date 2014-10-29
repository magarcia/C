# Python
import argparse
import os
import sys

# Third party
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tabulate import tabulate

# Set backend
backend = default_backend()
cipher = None
operation_modes = [mode for mode in modes.__dict__.keys() if mode.isupper()]

def build_cipher(key, iv, mode="CBC"):
    return Cipher(algorithms.AES(key), modes.__dict__[mode](iv), backend=backend)


def encrypt_message(message, key, iv):
    encryptor = cipher.encryptor()
    return encryptor.update(message)


def decrypt_message(crypt_message, key, iv):
    decryptor = cipher.decryptor()
    return decryptor.update(crypt_message)


def check_file(f):
    if not os.path.isfile(f):
        error('Error %s is not a file' % f)


def error(s):
    print(s)
    sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(
        prog="cryptaes",
        description='Encrypt/Decrypt AES files.'
    )

    parser.add_argument('file', metavar='file',
                        help='the file for encrypt or decrypt')

    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--encrypt', action='store_true')
    action.add_argument('--decrypt', action='store_false')

    parser.add_argument('--output', dest='output', required=True,
                        help='output file')

    iv = parser.add_mutually_exclusive_group()
    iv.add_argument('--iv', dest='iv', help='IV')
    iv.add_argument('--ivfile', dest='ivfile', help='input IV file')

    secret = parser.add_mutually_exclusive_group()
    secret.add_argument('--key', dest='secret', help='secret key')
    secret.add_argument('--keyfile',  dest='secretfile', help='input secret key file')

    parser.add_argument('--mode',  default="CBC", dest="mode",
                        help='operation mode %s [default: CBC]' % ', '.join(operation_modes))


    return parser.parse_args()


if __name__ == "__main__":

    args = parse_args()

    # Parse file
    check_file(args.file)
    op_file = open(args.file, 'rb').read()

    # Parse secret
    if args.secret is None and args.secretfile is None:
        args.secret = raw_input('Enter the SecretKey (16 bytes): ')

    elif args.secret is None:
        check_file(args.secretfile)
        args.secret = open(args.secretfile, 'rb').read()

    if len(args.secret) != 16:
        error(' '.join(
            ['Invalid SecretKey length, %d byes.' % len(args.secret),
             '16 bytes required.']
        ))

    # Parse IV
    random_iv = False
    if args.iv is None and args.ivfile is None:
        if args.encrypt:
            random_iv = raw_input('Use random IV [Y/n]?')
            random_iv = (random_iv is '') or (random_iv.lower() in ['y', 'yes'])
            if random_iv:
                args.iv = os.urandom(16)

        if not random_iv:
            args.iv = raw_input('Enter the IV (16 bytes): ')

    elif args.iv is None:
        check_file(args.ivfile)
        args.iv = open(args.ivfile, 'rb').read()

    if len(args.iv) != 16:
        error(' '.join(
            ['Invalid IV length, %d bytes.' % len(args.iv),
             '16 bytes required.']
        ))

    # Parse operation mode
    if not args.mode in operation_modes:
        error("%s isn't a valid operation mode." % args.mode)

    # Initialize cipher
    cipher = build_cipher(args.secret, args.iv, args.mode)

    # Encrypt/Decrypt message
    if args.encrypt:
        dec = op_file
        out = encrypt_message(dec, args.secret, args.iv)
        enc = out
    else:
        enc = op_file
        out = decrypt_message(enc, args.secret, args.iv)
        dec = out

    # Save output
    open(args.output, 'wb').write(out)
    if random_iv:
        open("%s.iv" % args.output, 'wb').write(args.iv)

    # Print info output
    hex_key = ":".join("{:02x}".format(ord(c)) for c in args.secret)
    hex_iv = ":".join("{:02x}".format(ord(c)) for c in args.iv)

    el = len(enc)
    ehex_file = ":".join("{:02x}".format(ord(c)) for c in enc[:7])
    ehex_file += ' [...] '
    ehex_file += ":".join("{:02x}".format(ord(c)) for c in enc[el-7:el])

    dl = len(dec)
    dhex_file = ":".join("{:02x}".format(ord(c)) for c in dec[:7])
    dhex_file += ' [...] '
    dhex_file += ":".join("{:02x}".format(ord(c)) for c in dec[dl-7:dl])

    print(tabulate(
        [
            ['Name', 'Bytes', 'Content'],
            ['Encrypted', el, ehex_file],
            ['Decrypted', dl, dhex_file],
            ['Key', len(args.secret), hex_key],
            ['IV', len(args.iv), hex_iv],
        ],
        headers="firstrow"
    ))
