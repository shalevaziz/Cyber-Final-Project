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
class Sender:
    def __init__(self, local_ip, local_port, dest_ip, dest_port, key):
        self.local_ip = local_ip
        self.local_port = local_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind((self.local_ip, self.local_port))
        self.stream = True

        self.frames = []
        self.cam = dxcam.create()
        self.cam.start(target_fps = 24)

        self.key = key
        self.cipher = Cipher_ECB(self.key)

    def start_stream(self):
        while self.stream:
            frame = self.take_screenshot()
            packets = self.split_into_packets(frame)
            self.send_data(packets)
        
    def take_screenshot(self):
        """This function takes a screenshot of the screen.

        Returns:
            bytes: The screenshot of the screen.
        """
        """frame = pyautogui.screenshot()
        frame = np.array(frame)
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        frame = cv2.resize(frame, RESULUTIONS, interpolation=cv2.INTER_AREA)"""
        frame = self.cam.get_latest_frame()
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        frame = cv2.resize(frame, RESULUTIONS, interpolation=cv2.INTER_AREA)
        result, frame = cv2.imencode('.jpg', frame)
        frame = frame.tobytes()
        return frame

    def split_into_packets(self, data):
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
            packets[i] = self.cipher.encrypt(packets[i])
        #print(len(packets[0]), len(packets))
        """first = str(hex(len(packets))).zfill(4).encode()
        packets.insert(0, first)"""
        
        packets = packets[::-1]

        return packets

    def send_data(self, packets):
        """This function sends data to the client

        Args:
            data (bytes): The data to send.
        """

        for packet in packets:
            self.s.sendto(packet, (self.dest_ip, self.dest_port))
            time.sleep(0.001)
            


def main():
    sender = Sender('192.168.68.115', 25566, '192.168.68.132', 25565, b'1234567812345678')
    sender.start_stream()


if __name__ == '__main__':
    main()