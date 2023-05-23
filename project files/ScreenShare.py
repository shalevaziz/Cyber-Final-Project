import cv2
import numpy as np
import socket
import pyautogui
import threading
from basics import Cipher_ECB
import time

RESOLUTIONS: tuple[int, int] = (1536, 864)
PACKET_SIZE: int = 65504
HEADER_SIZE: int = 7


class Sender:
    def __init__(self, local_ip: str, local_port: int, dest_ip: str, dest_port: int, key: bytes):
        self.local_ip = local_ip
        self.local_port = local_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind((self.local_ip, self.local_port))
        self.stream = True

        self.frames = []

        self.key = key
        self.cipher = Cipher_ECB(self.key)

    def wait_for_stop(self):
        msg, _ = self.s.recvfrom(16)
        if self.cipher.decrypt(msg) == b'STOP000000000000':
            self.stream = False

    def start_stream(self):
        threading.Thread(target=self.wait_for_stop).start()
        while self.stream:
            frame = self.take_screenshot()
            packets = self.split_into_packets(frame)
            self.send_data(packets)
        print('stopped')
        
    def take_screenshot(self):
        """This function takes a screenshot of the screen.

        Returns:
            bytes: The screenshot of the screen.
        """
        frame = pyautogui.screenshot()
        frame = np.array(frame)
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        frame = cv2.resize(frame, RESOLUTIONS, interpolation=cv2.INTER_AREA)
        frame = np.array(pyautogui.screenshot())
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        frame = cv2.resize(frame, RESOLUTIONS, interpolation=cv2.INTER_AREA)
        result, frame = cv2.imencode('.jpg', frame)
        frame = frame.tobytes()
        return frame

    def split_into_packets(self, data: bytes):
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

        packets = packets[::-1]

        return packets

    def send_data(self, packets: list[bytes]):
        """This function sends data to the client

        Args:
            packets (list[bytes]): The data to send.
        """

        for packet in packets:
            self.s.sendto(packet, (self.dest_ip, self.dest_port))
            time.sleep(0.001)
class MultiSender(Sender):
    """A class that broadcasts this PC's screen to multiple remote destinations.

    Attributes:
        local_ip (str): The local IP address to bind the socket to.
        local_port (int): The local port to bind the socket to.
        dest_port (int): The port of the remote destinations.
        key (bytes): The encryption key to use for encrypting the data.
    """
    def __init__(self, local_port: int, dest_port: int, key: bytes):
        super().__init__('0.0.0.0', local_port, '255.255.255.255', dest_port, key)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def stop(self):
        """A function that stops the stream.
        """
        self.stream = False
        self.s.sendto(self.cipher.encrypt(b'STOP000000000000'), (self.dest_ip, self.dest_port))
class Receiver:
    def __init__(self, local_ip: str, local_port: int, key: bytes, student_mode: bool = False):
        self.local_ip = local_ip
        self.local_port = local_port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind((self.local_ip, self.local_port))
        
        self.cipher = Cipher_ECB(key)
        self.lock = threading.Lock()
        
        self.student_mode = student_mode
    
    def stop(self):
        """This function stops the stream.
        """
        self.stream = False
        
    
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
        first, _ = self.s.recvfrom(PACKET_SIZE)
        first = self.cipher.decrypt(first)
        data_len = int.from_bytes(first[:3], 'big')
        num_packets = int.from_bytes(first[3:5], 'big')
        packets.append(first[5:])
        
        for i in range(num_packets-1):
            packet, _ = self.s.recvfrom(PACKET_SIZE)
            packet = self.cipher.decrypt(packet)
            packets.append(packet[5:])
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
        screen_name = 'Teacher\'s Screen' if self.student_mode else 'Student\'s Screen'
        while len(self.data) == 0:
            pass
        
        if self.student_mode:
            cv2.namedWindow(screen_name, cv2.WINDOW_NORMAL)
            cv2.setWindowProperty(screen_name, cv2.WND_PROP_FULLSCREEN, cv2.WINDOW_FULLSCREEN)
        
        while self.stream:
            self.lock.acquire()
            img = cv2.imdecode(np.frombuffer(self.data, np.uint8), cv2.IMREAD_COLOR)
            try:
                cv2.imshow(screen_name, img)
            except:
                pass
            self.lock.release()
            
            if not self.student_mode:
                try:
                    state = cv2.getWindowProperty(screen_name, 0)
                except cv2.error as e:
                    state -= 1
                    print(state)
                    print(e)
            
            if state < 0:
                self.stream = False
                cv2.destroyAllWindows()
                break
            
            cv2.waitKey(1)

    def recv_frames(self):
        """This function continuously receives frames from the server.

        Args:
            s (socket): The socket to receive data from.
        """
        while self.stream:
            self.data = self.recv_frame()


def main():
    send = Sender(
        local_ip='192.168.68.121',
        local_port=25566,
        dest_ip='192.168.68.115',
        dest_port=25565,
        key=b'1234567890123456'
    )
    send.start_stream()
    

if __name__ == '__main__':
    main()