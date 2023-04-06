from mss import mss
import time
from PIL import Image
from zlib import compress, decompress
import socket
class ScreenShare_Viewer:
    def __init__(self):
        """This function initializes the ScreenShare
        """
        self.socket_UDP = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_UDP.bind(('0.0.0.0', 25566))

class ScreenShare_Sharer:
