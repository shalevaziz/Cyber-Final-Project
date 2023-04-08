from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import time
class Cipher_DES:
    """This class is used to encrypt and decrypt messages using DES mode.
    It also authenticates the messages using HMAC.
    """
    def __init__(self, key=None, bytes=8):
        """This function initializes the cipher.

        Args:
            key (bytes, optional): The key to use. If None, a random key is generated. Defaults to None.
            bytes (int, optional): The number of bytes to use for the key. Defaults to 32.
        """
        self.bytes = bytes
        if key == None:
            self.__key = get_random_bytes(bytes)
        else:
            self.__key = key
        
        self.__cipher = DES.new(self.__key, DES.MODE_ECB)
        
        
    def encrypt(self, msg):
        """This function encrypts the message

        Args:
            msg (bytes): The message to encrypt

        Returns:
            bytes: The encrypted message
        """
        ciphertext = self.__cipher.encrypt(pad(msg, DES.block_size))
        return ciphertext
    
    def decrypt(self, msg):
        """This function decrypts a full message(a message that includes the nonce, tag and ciphertext)

        Args:
            msg (bytes): The message to decrypt

        Returns:
            bytes: The decrypted message
        """
        ciphertext = msg
        return unpad(self.__cipher.decrypt(ciphertext), DES.block_size)       
        
    
    def set_key(self, key):
        """This function sets the key of the cipher.

        Args:
            key (bytes): The key to use.
        """
        if len(key) == self.bytes:
            self.__key = key
    
    def get_key(self):
        """This function returns the key of the cipher.

        Returns:
            bytes: The key of the cipher
        """
        return self.__key

def main():
    cipher = Cipher_DES()
    print(cipher.get_key())
    msg = b'Hello World!'
    for i in range(10000):
        ciphertext = cipher.encrypt(msg)
        plaintext = cipher.decrypt(ciphertext)

    

if __name__ == '__main__':
    main()