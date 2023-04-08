import socket
import cv2
import numpy as np
import time
import threading
import pyautogui

RESULUTIONS = (1536, 864)
QUALITY = 95

def take_screenshot():
    """This function takes a screenshot of the screen.

    Returns:
        bytes: The screenshot of the screen.
    """
    frame = pyautogui.screenshot()
    frame = np.array(frame)
    frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    frame = cv2.resize(frame, RESULUTIONS, interpolation=cv2.INTER_AREA)
    result, frame = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), QUALITY])
    frame = frame.tobytes()
    return frame

def split_into_packets(data):
    """This function splits the data into packets.

    Args:
        data (bytes): The data to split.

    Returns:
        list: The list of packets.
    """
    packets = [packets[i:i+4092] for i in range(0, len(data)-4092, 4092)]
    packets.append(data[-4092:])
    for i in range(len(packets)):
        packets[i] = str(hex(i)).zfill(4).encode() + packets[i]
    
    first = str(hex(len(packets))).zfill(4).encode()
    packets.insert(0, first)
    


    return packets

def send_data(packets, s, address):
    """This function sends data to the client

    Args:
        data (bytes): The data to send.
    """
    for packet in packets:
        s.sendto(packet, address)

def main():
    local_ip = '192.168.68.125'
    dest_ip = '192.168.68.113'
    port = 25565

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((local_ip, port))
    sct = take_screenshot()
    packets = split_into_packets(sct)
    send_data(packets, s, (dest_ip, port))
    