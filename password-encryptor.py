from argparse import ArgumentParser
from base64 import b64decode, b64encode
import sys

from Crypto.Cipher import AES


class PasswordEncryptor():
    """Encrypts or decrypts a given value."""
    # TODO: validate inputs
    # TODO: error handling

    _BLOCK_SIZE = 16

    @staticmethod
    def _pad_value(value):
        """Pads value to reach a length divisible by the requried block size"""
        block_size = PasswordEncryptor._BLOCK_SIZE
        return str(value) + " " * (block_size - len(value) % PasswordEncryptor._BLOCK_SIZE)

    @staticmethod
    def decrypt(encrypted_value, key, initialization_vector):
        """Returns the decrypted value using the provided key and initialization vector"""
        encryptor = AES.new(key, AES.MODE_CBC, initialization_vector)
        return encryptor.decrypt(b64decode(encrypted_value)).decode("utf-8").rstrip()

    @staticmethod
    def encrypt(value, key, initialization_vector):
        """Returns the encrypted value using provided the key and initialization vector"""
        encryptor = AES.new(key, AES.MODE_CBC, initialization_vector)
        value = PasswordEncryptor._pad_value(value)
        return b64encode(encryptor.encrypt(value)).decode("utf-8")


class PasswordEncryptorApp():
    """Implements a command line application for the PasswordEncryptor class"""

    def __init__(self):
        self.args = PasswordEncryptorApp._parse_arguments()

    @staticmethod
    def _parse_arguments():
        """Defines arguments to be parsed"""
        argument_parser = ArgumentParser(description="encrypt/decrypt a value using AES")
        argument_parser.add_argument(
            "--value", "-v",
            help="value to be encrypted/decrypted",
            required=True,
            type=str)
        argument_parser.add_argument(
            "--key", "-k",
            help="key to be used for encryption/decryption",
            required=True,
            type=str)
        argument_parser.add_argument(
            "--init_vector", "-i",
            dest="iv",
            help="initialization vector to be used for encryption/decryption",
            metavar="INITIALIZATION_VECTOR",
            required=True,
            type=str)
        argument_parser.add_argument(
            "--decrypt",
            const=True,
            default=False,
            dest="decrypt_mode",
            help="enable decryption mode",
            nargs="?",
            type=bool)

        return argument_parser.parse_args()

    def run(self):
        args = self.args
        if args.decrypt_mode:
            sys.stdout.write(PasswordEncryptor().decrypt(args.value, args.key, args.iv) + "\n")
            return 0
        
        sys.stdout.write(PasswordEncryptor().encrypt(args.value, args.key, args.iv) + "\n")
        return 0


if __name__ == "__main__":
    PasswordEncryptorApp().run()
