from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from .imgproc import *
import os


class ImageCryptoUtils:
    def __init__(self) -> None:
        pass

    @staticmethod
    def decrypt(img: Image, password: str) -> Image:
        """
        Decrypts an image using AES-192 in CTR mode
        :param img: image to be decrypted
        :param password: password for the PBKDF to generate the key
        :return: decrypted image
        """

        # get the iv from the image metadata
        metadata = ImageCryptoUtils.__read_metadata(img)
        iv = bytes.fromhex(metadata["aes_iv"])
        salt = bytes.fromhex(metadata["aes_key_salt"])
        x = int(metadata["encription_zone_x"])
        y = int(metadata["encription_zone_y"])
        width = int(metadata["encription_zone_width"])
        height = int(metadata["encription_zone_height"])

        # generate key from password
        key = PBKDF2HMAC(
            salt=salt,
            length=24,  # 24 bytes = 192 bits
            algorithm=hashes.SHA256(),
            iterations=100000
        ).derive(password.encode())

        # create cipher
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        decryptor = cipher.decryptor()

        # DECRYPT
        # get the pixels to decrypt
        pixels = getColors(img, x, y, width, height)
        new_pixels = {}
        for pixel, color in pixels.items():
            block = bytearray()
            block += decryptor.update(color)
            new_pixels[pixel] = block

        updatePixelsFromDict(img, x, y, width, height, new_pixels)

        return img

    @staticmethod
    def encrypt(img: Image, password: str, x, y, width, height) -> Image:
        """
        Encrypts an image using AES-192 in CTR mode
        :param img: image to be encrypted
        :param password: password for the PBKDF to generate the key
        :param x: x coordinate of the top left corner of square to encrypt
        :param y: y coordinate of the top left corner of square to encrypt
        :param width: width of the square to encrypt
        :param height: height of the square to encrypt
        """
        # generate key from password 
        # generate salt
        salt = os.urandom(16)
        key = PBKDF2HMAC(
            salt=salt,
            length=24,  # 24 bytes = 192 bits
            algorithm=hashes.SHA256(),
            iterations=100000
        ).derive(password.encode())
        # check if key is 192 bits = 24 bytes #FIXME REMOVE
        if len(key) != 24:
            raise ValueError("The key must be 192 bits, 24 bytes")

        # randomize iv 16 bytes for cbc in aes 192
        iv = os.urandom(16)

        # write the iv and salt in the image metadata
        metadata = {"aes_iv": iv.hex(),
                    "aes_key_salt": salt.hex(),
                    "encription_zone_x": x,
                    "encription_zone_y": y,
                    "encription_zone_width": width,
                    "encription_zone_height": height,
                    }
        ImageCryptoUtils._write_metadata(img, metadata)

        # create cipher
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        encryptor = cipher.encryptor()

        # ENCRYPT
        # get the pixels to encrypt 
        pixels = getColors(img, x, y, width, height)
        new_pixels = {}
        for pixel, color in pixels.items():
            block = bytearray()
            block += encryptor.update(color)  # color es un bytearray de 3 bytes
            new_pixels[pixel] = block

        updatePixelsFromDict(img, x, y, width, height, new_pixels)

        return img

    @staticmethod
    def _write_metadata(img: Image, new_metadata: dict) -> None:
        """
        updates the metadata of the image
        :param img: image
        :param new_metadata: new metadata to add
        """
        old_meta_data = img.info
        old_meta_data.update(new_metadata)
        img.info = old_meta_data

    @staticmethod
    def __read_metadata(img: Image) -> dict:
        """
        reads the metadata of the image
        :param img: image
        :return: metadata of the image
        """
        return img.info

    @staticmethod
    def generate_image_hash(img: Image) -> None:
        """
        Generates a hash of the image and writes it in the metadata
        :param img: image
        :return: None
        """
        key = os.urandom(32)  # 32 bytes = 256 bits para SHA256
        h = hmac.HMAC(key, hashes.SHA256())
        img_bytes = img.tobytes()

        iv = bytes.fromhex(ImageCryptoUtils.__read_metadata(img)["aes_iv"])
        salt = bytes.fromhex(ImageCryptoUtils.__read_metadata(img)["aes_key_salt"])
        # FIXME 
        # el key debe ir encriptado con RSA del server
        h.update(img_bytes + iv + salt + key)
        img_hash = h.finalize()
        ImageCryptoUtils._write_metadata(img, {"hash_key": key.hex()})
        return img_hash
