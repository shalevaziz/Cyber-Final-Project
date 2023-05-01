import socket
import cv2
import numpy as np
import time
import threading
import pickle
from basics import Cipher_ECB
RESULUTIONS = (1536, 864)
QUALITY = 95
PACKET_SIZE = 65504
data = b''
LOCK = threading.Lock()

def recv_packets(s, cipher):
    """This function receives packets from the server.

    Args:
        s (socket): The socket to receive data from.
    """
    packets = []

    LOCK.acquire()
    #s.sendto(b'1', ('192.168.68.113', 25566))
    first, _ = s.recvfrom(PACKET_SIZE)
    first = cipher.decrypt(first)
    data_len = int.from_bytes(first[:3], 'big')
    num_packets = int.from_bytes(first[3:5], 'big')
    packets.append(first[5:])
    
    for i in range(num_packets-1):
        packet, _ = s.recvfrom(PACKET_SIZE)
        packet = cipher.decrypt(packet)
        packets.append(packet[5:])
        #print(i)
    LOCK.release()

    packets = sorted(packets, key=lambda x: int.from_bytes(x[:2], 'big'))
    packets = [packet[2:] for packet in packets]
    data = b''.join(packets)
    data = data[:data_len]
    
    return data

def show_screenshot():
    """This function shows the screenshot.
    """
    global data
    while len(data) == 0:
        pass
    while True:
        LOCK.acquire()
        img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
        try:
            cv2.imshow('img', img)
        except:
            pass
        LOCK.release()

        cv2.waitKey(1)

def main():
    """This function starts the ScreenShare.
    """
    global data
    local_ip = '10.30.56.247'
    port = 25565
    

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((local_ip, port))

    t = threading.Thread(target=show_screenshot)
    t.start()
    c = Cipher_ECB(b'1234567812345678')
    while True:
        data = recv_packets(s, c)

        

if __name__ == '__main__':
    main()