"""
This is a library for AES Encrypted Image Format (AEIF).
It provides encryption, decryption, and hash verification functionality.
Created by: Pek
"""
from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class AEIFManager:
    """
    A class that provides encryption, decryption,
    and hash verification functionality for AES Encrypted Image Format (AEIF).
    """

    def __init__(self, key_path=''):
        """
        Initializes an instance of the AEIFManager class.

        Args:
            key_path (str): The path to the file containing the encryption key. Defaults to an empty string.
        """
        if key_path != '':
            with open(key_path, 'rb') as key_file:
                self.key = key_file.read()

    def encrypt(self, input_path: str, output_path: str, key_path='', key=b'', iv=b'') -> str:
        """
        Encrypts an image file using AES encryption in GCM mode.

        Args:
            input_path (str): The path to the input image file.
            output_path (str): The path to save the encrypted image file.
            key_path (str): The path to the file containing the encryption key. Defaults to an empty string.
            key (bytes): The encryption key as bytes. Defaults to an empty bytes object.
            iv (bytes): The initialization vector (IV) as bytes. Defaults to an empty bytes object.

        Returns:
            str: The path to the encrypted image file.
        """
        # Read the image as bytes
        with open(input_path, 'rb') as image_file:
            image_bytes = image_file.read()
        
        # Read the key as bytes if not provided
        if key == b'':
            if self.key == b'':
                with open(key_path, 'rb') as key_file:
                    key = key_file.read()
            else:
                key = self.key

        # Generate a random 96-bit IV (Initialization Vector) if not provided
        if iv == b'':
            iv = get_random_bytes(12)

        # Create an AES cipher object in GCM mode
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

        # Encrypt the padded data
        encrypted_data, tag = cipher.encrypt_and_digest(pad(image_bytes, AES.block_size))

        # Write the IV, tag, and encrypted data to a new file with .aeif extension
        with open(output_path, 'wb') as encrypted_file:
            encrypted_file.write(iv)
            encrypted_file.write(tag)
            encrypted_file.write(encrypted_data)

        return output_path

    def decrypt(self, input_path: str, output_path: str, key_path='', key=b'') -> str:
        """
        Decrypts an encrypted image file using AES decryption in GCM mode.

        Args:
            input_path (str): The path to the input encrypted image file.
            output_path (str): The path to save the decrypted image file.
            key_path (str): The path to the file containing the encryption key. Defaults to an empty string.
            key (bytes): The encryption key as bytes. Defaults to an empty bytes object.

        Returns:
            str: The path to the decrypted image file.
        """
        # Read the encrypted data
        with open(input_path, 'rb') as encrypted_file:
            iv = encrypted_file.read(12)
            tag = encrypted_file.read(16)
            encrypted_data = encrypted_file.read()
        
        # Read the key as bytes if not provided
        if key == b'':
            if self.key == b'':
                with open(key_path, 'rb') as key_file:
                    key = key_file.read()
            else:
                key = self.key

        # Create an AES cipher object in GCM mode
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

        # Decrypt the data and verify the tag
        decrypted_data = unpad(cipher.decrypt_and_verify(encrypted_data, tag), AES.block_size)

        # Write the decrypted data to a new file with .png extension
        with open(output_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        return output_path

def verify_hash(file_paths: tuple) -> bool:
    """
    Verifies the hash of two files.

    Args:
        file_paths (tuple): A tuple containing the paths to the two files to compare.

    Returns:
        bool: True if the hash of the two files matches, False otherwise.
    """
    file_path_1, file_path_2 = file_paths

    with open(file_path_1, 'rb') as file_1:
        with open(file_path_2, 'rb') as file_2:
            hash1 = sha256(file_1.read()).hexdigest()
            hash2 = sha256(file_2.read()).hexdigest()
            return hash1 == hash2

def genkey(output_path: str, size=16) -> tuple:
    """
    Generate a random key with the specified size and save it to a file.

    Args:
        output_path (str): The path to save the generated key.
        size (int, optional): The size of the key in bytes. Defaults to 16.

    Returns:
        tuple: A tuple containing the output path and the generated key.
    """
    # Generate a random key with the specified size
    key = get_random_bytes(size)
    with open(output_path, 'wb') as key_file:
        key_file.write(key)

    return output_path, key
