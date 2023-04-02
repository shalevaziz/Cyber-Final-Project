import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import Crypto
import socket
from threading import Thread
#random number generator
import random
#create random text length 4096
chars = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', ' ', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '[', ']', '{', '}', ';', ':', "'", '"', ',', '.', '<', '>', '/', '?', '`', '~']
text = ''
for i in range(4096):
    text += chars[random.randint(0, len(chars) - 1)]
with open('text.txt', 'w') as f:
    f.write(text)
"""cipher_client = AES.new(key, AES.MODE_EAX)
cipher_client.update(b"")
ciphertext, tag = cipher_client.encrypt_and_digest(b"Hello World")
#decrypt
cipher_server = AES.new(key, AES.MODE_EAX, cipher_client.nonce)
plaintext = cipher_server.decrypt_and_verify(ciphertext, tag)
print(len(cipher_client.nonce))

ciphertext, tag = cipher_client.encrypt_and_digest(b"Hello World")
#decrypt
plaintext = cipher_server.decrypt_and_verify(ciphertext, tag)
print(plaintext)"""



