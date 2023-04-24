from operator import le
import socket
import cv2
import numpy as np
import time
import threading
import pyautogui
import pickle
from basics import Cipher_ECB
import dxcam


RESULUTIONS = (1536, 864)
QUALITY = 95
PACKET_SIZE = 65504
HEADER_SIZE = 7

def take_screenshot(camera):
    """This function takes a screenshot of the screen.

    Returns:
        bytes: The screenshot of the screen.
    """
    """frame = pyautogui.screenshot()
    frame = np.array(frame)
    frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    frame = cv2.resize(frame, RESULUTIONS, interpolation=cv2.INTER_AREA)"""
    frame = camera.get_latest_frame()
    frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    frame = cv2.resize(frame, RESULUTIONS, interpolation=cv2.INTER_AREA)
    result, frame = cv2.imencode('.jpg', frame)
    frame = frame.tobytes()
    return frame

def split_into_packets(data, cipher):
    """This function splits the data into packets.

    Args:
        data (bytes): The data to split.

    Returns:
        list: The list of packets.
    """
    data = data + b'0'*(PACKET_SIZE - len(data) % PACKET_SIZE)
    data_size_in_packet = PACKET_SIZE - HEADER_SIZE
    packets = [data[i:i+data_size_in_packet] for i in range(0, len(data)-data_size_in_packet, data_size_in_packet)]
    num_of_packets = len(packets).to_bytes(2, 'big')
    len_data = len(data).to_bytes(3, 'big')

    for i in range(len(packets)):
        packets[i] = len_data + num_of_packets + i.to_bytes(2, 'big') + packets[i]
        packets[i] = cipher.encrypt(packets[i])
    #print(len(packets[0]), len(packets))
    """first = str(hex(len(packets))).zfill(4).encode()
    packets.insert(0, first)"""
    
    packets = packets[::-1]

    return packets

def send_data(packets, s, address):
    """This function sends data to the client

    Args:
        data (bytes): The data to send.
    """
    #data = s.recvfrom(1)
    #print(data)
    #i = 0
    for packet in packets:
        s.sendto(packet, address)
        time.sleep(0.001)
        #time.sleep(0.01)
        #print(i)
        #i += 1


def main():
    local_ip = '10.30.57.24'
    local_port = 25566
    dest_ip = '10.30.56.247'
    dest_port = 25565

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((local_ip, local_port))
    start = time.time()
    timings = []
    c = Cipher_ECB(b'1234567812345678')
    camera = dxcam.create()
    camera.start(target_fps = 24)
    for i in range(500):
        #timings.append(time.time())
        sct = take_screenshot(camera)
        #timings.append(time.time())
        packets = split_into_packets(sct, c)
        #timings.append(time.time())
        send_data(packets, s, (dest_ip, dest_port))
        #timings.append(time.time())

    for i in range(len(timings)-1):
        print(timings[i+1] - timings[i])
    print(time.time() - start)

if __name__ == '__main__':
    main()