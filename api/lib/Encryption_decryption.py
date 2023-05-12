'''
    This module contains functions for encrypting and decrypting data.

    Import os to store environment variables
    Import json to convert dict to json string format
    Import AES for encryption
    Import get_random_bytes to generate random bytes
    Import secrets to generate secret header
'''
import os
import json

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import secrets


def encrypt_data(payload: str) -> bytes:
    """
    Encrypts the given payload using a randomly generated key and nonce.

    Args:
        payload (str): The plaintext data to be encrypted.

    Returns:
        Tuple[bytes, bytes, bytes, bytes, bytes]: A tuple containing the header, key, ciphertext,
            tag, and nonce used for encryption.

    """
    payload = payload.encode('utf-8')
    
    # Generate a random header.
    header = secrets.token_bytes(16)
    # Generate a random key.
    key = get_random_bytes(16)
    # Create an AES cipher object.
    cipher = AES.new(key, AES.MODE_GCM)
    # Update the cipher object with the header.
    cipher.update(header)
    # Encrypt the payload.
    cipher_text, tag = cipher.encrypt_and_digest(payload)
    nonce = cipher.nonce


    crypto_values = {"header": header, "key": key, "tag": tag, "nonce": nonce}
    print(f'Crypto values => {crypto_values}')
    crypto_values_string = json.dumps(crypto_values)
    print(crypto_values_string)
    os.environ["CRYPTO_VALUES"] = crypto_values_string

    return cipher_text


def decrypt_data(ciphertext: bytes) -> str:
    """
    Decrypts the given ciphertext using the specified key, nonce, and tag.

    Args:
        header (bytes): The header bytes that were used to encrypt the data.
        key (bytes): The encryption key used to encrypt the data.
        cipher_text (bytes): The ciphertext to be decrypted.
        tag (bytes): The tag value used to authenticate the data.
        nonce (bytes): The nonce value used to encrypt the data.

    Returns:
        str: The decrypted plaintext as a string.

    Raises:
        ValueError: If the provided tag does not match the expected tag.

    """
    #  # Get the header from the environment variable.
    # header = os.environ["HEADER"]
    # header = header.encode('utf-8')
    # # Get the key from the environment variable.
    # key = os.environ["KEY"]
    # key = key.encode('utf-8')
    # # Get the tag from the environment variable.
    # tag = os.environ["TAG"]
    # tag = tag.encode('utf-8')
    # # Get the nonce from the environment variable.
    # nonce = os.environ["NONCE"]
    # nonce = nonce.encode('utf-8')
    crypto_values_string = os.environ["CRYPTO_VALUES"]
    crypto_values = json.loads(crypto_values_string)
    header = crypto_values["header"]
    key = crypto_values["key"]
    tag = crypto_values["tag"]
    nonce = crypto_values["nonce"]

    # Create an AES cipher object.
    decrypt_cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # Update the cipher object with the header.
    decrypt_cipher.update(header)

    # Decrypt the ciphertext.
    try:
        plain_text = decrypt_cipher.decrypt_and_verify(cipher_text, tag)
    except ValueError:
        raise ValueError("Invalid authentication tag. The provided tag does not match the expected tag.")

    # Return the decrypted plaintext as a string.
    return plain_text.decode('utf-8')


cipher_text = encrypt_data('secret data')
# msg = decrypt_data(cipher_text)
# print(msg)