import socket
import cv2
import numpy as np
import time
import threading
import pyautogui

RESULUTIONS = (1536, 864)
QUALITY = 95

packets = []
data = b''


def recv_packets(s):
    """This function receives packets from the server.

    Args:
        s (socket): The socket to receive data from.
"""
    global packets
    first = s.recvfrom(4)
    num_packets = int(first[0].decode(), 16)

    for i in range(num_packets):
        packet = s.recvfrom(4096)
        packets.append(packet)
    print('Received all packets')
    packets = sorted(packets, key=lambda x: int(x[:4].decode(), 16))
    packets = [packet[4:] for packet in packets]
    data = b''.join(packets)

def show_screenshot():
    """This function shows the screenshot.
    """
    global data
    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    cv2.imshow('img', img)
    cv2.waitKey(1)

def main():
    """This function starts the ScreenShare.
    """
    local_ip = '192.168.68.113'
    port = 25565

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((local_ip, port))




        
    