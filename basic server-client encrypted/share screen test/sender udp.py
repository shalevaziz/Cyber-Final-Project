import socket
import cv2
import numpy as np
import time
import threading
import pyautogui
import pickle

RESULUTIONS = (1536, 864)
QUALITY = 95
PACKET_SIZE = 65507
HEADER_SIZE = 7

def take_screenshot():
    """This function takes a screenshot of the screen.

    Returns:
        bytes: The screenshot of the screen.
    """
    frame = pyautogui.screenshot()
    frame = np.array(frame)
    frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    frame = cv2.resize(frame, RESULUTIONS, interpolation=cv2.INTER_AREA)
    
    result, frame = cv2.imencode('.jpg', frame)
    frame = frame.tobytes()
    return frame

def split_into_packets(data):
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
    local_ip = '192.168.68.113'
    local_port = 25566
    dest_ip = '192.168.68.113'
    dest_port = 25565

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((local_ip, local_port))
    start = time.time()
    for i in range(1000):
        sct = take_screenshot()
        with open('screenshot', 'wb') as f:
            f.write(sct)
        packets = split_into_packets(sct)
        send_data(packets, s, (dest_ip, dest_port))
        
    print(time.time() - start)

if __name__ == '__main__':
    main()