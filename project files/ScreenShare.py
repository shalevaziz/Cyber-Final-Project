import socket
import cv2
import numpy as np
import time
import threading
import pyautogui
import pickle
from basics import Cipher_ECB
#import dxcam


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
        """self.cam = dxcam.create()
        self.cam.start(target_fps = 24)"""

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
        frame = np.array(pyautogui.screenshot())
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


    
class Receiver:
    def __init__(self, local_ip, local_port, key):
        self.local_ip = local_ip
        self.local_port = local_port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind((self.local_ip, self.local_port))
        
        self.cipher = Cipher_ECB(key)
        self.lock = threading.Lock()
        
    def start_stream(self):
        """This function starts the stream.
        """
        self.stream = True
        self.data = b''
        self.thread = threading.Thread(target=self.recv_frames)
        self.thread.start()
        self.show_screenshots()
    
    def recv_frame(self):
        """This function receives packets from the server.

        Args:
            s (socket): The socket to receive data from.
        """
        packets = []

        self.lock.acquire()
        #s.sendto(b'1', ('192.168.68.113', 25566))
        first, addr = self.s.recvfrom(PACKET_SIZE)
        self.dest_addr = addr
        first = self.cipher.decrypt(first)
        data_len = int.from_bytes(first[:3], 'big')
        num_packets = int.from_bytes(first[3:5], 'big')
        packets.append(first[5:])
        
        for i in range(num_packets-1):
            packet, _ = self.s.recvfrom(PACKET_SIZE)
            packet = self.cipher.decrypt(packet)
            packets.append(packet[5:])
            #print(i)
        self.lock.release()

        packets = sorted(packets, key=lambda x: int.from_bytes(x[:2], 'big'))
        packets = [packet[2:] for packet in packets]
        data = b''.join(packets)
        data = data[:data_len]
        
        return data

    def show_screenshots(self):
        """This function shows the screenshot.
        """
                
        state = 1
        
        while len(self.data) == 0:
            pass
        
        while self.stream:
            self.lock.acquire()
            img = cv2.imdecode(np.frombuffer(self.data, np.uint8), cv2.IMREAD_COLOR)
            try:
                state = cv2.getWindowProperty('frame', 0)
            except cv2.error as e:
                state -= 1
                print(state)
                print(e)

            try:
                cv2.imshow('frame', img)
            except:
                pass
            self.lock.release()
            
            
            if state < 0:
                self.stream = False
                cv2.destroyAllWindows()
                break
            
            cv2.waitKey(1)
        
        msg = b'STOP000000000000'
        self.s.sendto(self.cipher.encrypt(msg), self.dest_addr)

    def recv_frames(self):
        """This function continuously receives frames from the server.

        Args:
            s (socket): The socket to receive data from.
        """
        while self.stream:
            self.data = self.recv_frame()

def main():
    """sender = Receiver('0.0.0.0', 25566, b'1234567812345678')
    sender.start_stream()"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(('0.0.0.0', 25565))
    msg, addr = s.recvfrom(1024)
    print(msg)


if __name__ == '__main__':
    main()