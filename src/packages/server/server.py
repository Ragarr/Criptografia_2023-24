from .user import User
from PIL import Image, PngImagePlugin
from .storage_manager import StorageManager
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.scrypt  import Scrypt
from cryptography.hazmat.primitives.asymmetric import rsa, padding 
from cryptography.exceptions import InvalidSignature

import re
import uuid


class Server():
    def __init__(self) -> None:
        self.__sm = StorageManager()
        self.__sm.create_directories()

    def __get_users(self) -> list:
        """Returns the list of users
        Returns:
            list: list of users
        """
        return self.__sm.get_users()
    
    def __remove_user(self, user: User) -> None:
        """Removes the given user
        Args:
            user (User): user to be removed
        """
        users = self.__get_users()
        for usr in users:
            if user == usr.name:
                users.remove(usr)
        self.__sm.remove_images(user)
        self.__sm.update_users_json(users)

    def create_user(self, name, password) -> None:
        """Creates a new user with the given name and password
        Args:
            name (str): name of the user
            password (str): password of the user (hashed)
        """
        # check if name is unique
        users = self.__get_users()
        for user in users:
            if user.name == name:
                raise ValueError("Name is already taken")
            
        
        # TODO la contraseña estara encriptada con RSA y el servidor tendra la clave privada
        # TODO desencriptar la contraseña con la clave privada del servidor
        # comprobar que la contraseña cumple los requisitos 
        # 12 caracteres, 1 mayuscula, 1 minuscula, 1 numero, 1 caracter especial
        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters long")
        elif not re.search("[a-z]", password):
            raise ValueError("Password must contain at least one lowercase letter")
        elif not re.search("[A-Z]", password):
            raise ValueError("Password must contain at least one uppercase letter")
        elif not re.search("[0-9]", password):
            raise ValueError("Password must contain at least one number")
        elif not re.search("[!@#$%^&*()_+-={};':\"\\|,.<>/?]", password):
            raise ValueError("Password must contain at least one special character")
        
        # KDF de la contraseña
        salt_p = uuid.uuid4().hex # son 16 bytes = 198 bits
        kdf = Scrypt(
            salt = bytes.fromhex(salt_p),
            length = 32, # 256 bits
            n = 2**14,
            r = 8,
            p = 1
        )
        password = kdf.derive(bytes(password, "utf-8")).hex()  
        # create user
        users = self.__get_users()
        users.append(User(name, password, salt_p))
        self.__sm.update_users_json(users)
        

    def remove_user(self, name: str, password: str):
        """Removes the user with the given name
        Args:
            name (str): name of the user
            password (str): password of the user (hashed)
        """
        if name == "":
            raise ValueError("Name cannot be empty")
        elif password == "":
            raise ValueError("Password cannot be empty")
        
        # check if user exists and if password is correct
        if self.__authenticate(name=name, password=password):
            self.__remove_user(name)
        else:
            raise ValueError("User not found")

    def store_image(self, image: Image, user_name, password):
        """ Stores the image in the server, IMAGE FORMAT: PNG
        Args:
            image_path (str): path to the image 
            camera_name (str): name of the camera
            user_name (str): name of the owner
        """
        if user_name == "" or user_name is None:
            raise ValueError("User cannot be empty")
        if image is None:
            raise ValueError("Image cannot be empty")
        

        # check if owner is valid and if password is correct
        if not self.__authenticate(user_name, password):
            raise ValueError("User or password incorrect")
        
        
        # checK  tags #TODO
        pass
        # check hash signature #TODO

        # get metadata
        image_metadata = image.info

        # regenerate hash
        img_bytes = image.tobytes()
        iv = bytes.fromhex(image_metadata["aes_iv"])
        salt = bytes.fromhex(image_metadata["aes_key_salt"])
        key = bytes.fromhex(image_metadata["hash_key"])

        h = hmac.HMAC(key, hashes.SHA256())
        h.update(img_bytes + iv + salt + key)
        img_hash = h.finalize()

        
        # check hash signature
        hash_sign = image_metadata["signature"]
        # get public key # FIXME
        public_key = image_metadata["public_key"]
        public_key = serialization.load_pem_public_key(
            bytes.fromhex(public_key)
        )
        # decript hash signature
        try:
            public_key.verify(
                bytes.fromhex(hash_sign),
                img_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            print("Invalid signature")
            return 
        

        
        # check certificate #TODO
        pass
        # store image 
        
        # dev and debug purposes
        image.load()

        # META DATA
        # copy metadata from original image to new image
        info = PngImagePlugin.PngInfo()
        for key, value in image.info.items():
            info.add_text(str(key), str(value))
        # add new metadata
        
        # store image
        self.__sm.storage_img(image, user_name, info)
    
    def get_images(self, num: int, username: str | None = None, date: str | None =None, time: str | None = None) -> list:
        """Returns a list of images from the given camera
        Args:
            num (int): number of images to return
            author (str, optional): name of the  owner. Defaults to None.
            date (str, optional): date of the images. Defaults to None.
                format: "%Y/%m/%d"
            time (str, optional): time of the images. Defaults to None.
                format: HH_MM_SS
        Returns:
            list: list of images
        """
        # CHECKS #TODO

        # get images
        return self.__sm.get_images(num, username, date, time)

    def login(self, name: str, password: str) -> bool:
        """Logs in a user
        Args:
            name (str): name of the user
            password (str): password of the user
        Returns:
            bool: True if the user was logged in, False otherwise
        """
        # update users
        users = self.__get_users()

        # check if user exists
        usernames = [ user.name for user in users ]
        if name not in usernames:
            return False
        
        # check if password is correct
        return self.__authenticate(name, password)
    
    def remove_image(self, username: str, password:str, date: str, time: str) -> None:
        """Removes the image with the given name
        Args:
            username (str): name of the user
            date (str): date of the image
            time (str): time of the image
        """
        if username == "" or username is None:
            raise ValueError("Username cannot be empty")
        elif date == "":
            raise ValueError("Date cannot be empty")
        elif time == "":
            raise ValueError("Time cannot be empty")
        
        if not self.__authenticate(username, password):
            raise ValueError("User or password incorrect")
        
        self.__sm.remove_image(username, date, time)

    
    def __authenticate(self, name: str, password: str) -> bool:
        # get users salt and password
        auth = False
        users = self.__get_users()
        for user in users:
            if user.name == name:
                # generate kdf with salt
                kdf = Scrypt(
                    salt = bytes.fromhex(user.salt_p),
                    length = 32,
                    n = 2**14,
                    r = 8,
                    p = 1
                )
                derivated_pass = kdf.derive(bytes(password, "utf-8")).hex()

                if user.password == derivated_pass:
                    auth = True
                    # update salt and password
                    user.salt_p = uuid.uuid4().hex
                    kdf = Scrypt(
                        salt = bytes.fromhex(user.salt_p),
                        length = 32,
                        n = 2**14,
                        r = 8,
                        p = 1
                    )
                    user.password = kdf.derive(bytes(password, "utf-8")).hex()
                    self.__sm.update_users_json(users)
                    break
        
        return auth
    
    def clear_server(self):
        """Clears the server
        """
        # REMOVE AFTER TESTING
        self.__sm.delete_all_images()
        self.__sm.delete_all_users()
        self.__sm.create_directories()
        print("Server cleared")