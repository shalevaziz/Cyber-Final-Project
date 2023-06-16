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
    """This class streams the screen to the Receiver.
    """
    def __init__(self, local_ip: str, local_port: int, dest_ip: str, dest_port: int, key: bytes):
        """
        Initializes a Sender object with the specified local and destination IP addresses, ports and encryption key.

        Args:
            local_ip (str): The local IP address to bind the socket to.
            local_port (int): The local port to bind the socket to.
            dest_ip (str): The IP address of the remote destination.
            dest_port (int): The port of the remote destination.
            key (bytes): The encryption key to use for data transmission.

        Returns:
            None
        """
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

    def wait_for_stop(self) -> None:
        """
        Waits for a stop signal from the Receiver.
        This is used to stop the streaming from the student when the teacher stops it.

        Returns:
            None
        """
        msg, _ = self.s.recvfrom(16)
        if self.cipher.decrypt(msg) == b'STOP000000000000':
            self.stream = False
            print('stop')

    def start_stream(self) -> None:
        """
        Starts the stream and sends data to the client.

        Returns:
            None
        """
        threading.Thread(target=self.wait_for_stop).start()
        while self.stream:
            frame = self.take_screenshot()
            packets = self.split_into_packets(frame)
            self.send_data(packets)
        print('stopped')
        
    def take_screenshot(self) -> bytes:
        """
        Takes a screenshot of the screen.

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

    def split_into_packets(self, data: bytes) -> list[bytes]:
        """
        Splits the data into packets.

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

    def send_data(self, packets: list[bytes]) -> None:
        """
        Sends data to the client.

        Args:
            packets (list[bytes]): The data to send.

        Returns:
            None
        """
        try:
            for packet in packets:
                self.s.sendto(packet, (self.dest_ip, self.dest_port))
                time.sleep(0.001)#The receiver can't handle the data if it's sent too fast.
        except OSError:
            pass
class MultiSender(Sender):
    """A class that broadcasts this PC's screen to multiple remote destinations.

    Attributes:
        local_ip (str): The local IP address to bind the socket to.
        local_port (int): The local port to bind the socket to.
        dest_port (int): The port of the remote destinations.
        key (bytes): The encryption key to use for encrypting the data.
    """
    def __init__(self, local_port: int, dest_port: int, key: bytes):
        """Initializes a ScreenShare object with the specified local and destination ports and encryption key.

        Args:
            local_port (int): The local port to bind to.
            dest_port (int): The destination port to send data to.
            key (bytes): The encryption key to use for data transmission.

        Returns:
            None
        """
        super().__init__('0.0.0.0', local_port, '255.255.255.255', dest_port, key)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def start_stream(self):
        """A function that starts the stream and sends data to the clients.
        """
        while self.stream:
            frame = self.take_screenshot()
            packets = self.split_into_packets(frame)
            self.send_data(packets)
        print('stopped')
    
    def stop_stream(self):
        """A function that stops the stream.
        """
        self.stream = False

class Receiver:
    """A class that receives the screen data from the sender.
    """
    def __init__(self, local_ip: str, local_port: int, key: bytes, student_mode: bool = False) -> None:
        """
        Initializes a Receiver object with the specified local IP, local port, encryption key, and student mode.

        Args:
            local_ip (str): The local IP address to bind the socket to.
            local_port (int): The local port to bind the socket to.
            key (bytes): The encryption key to use for decrypting the data.
            student_mode (bool): A boolean indicating whether the receiver is in student mode.

        Returns:
            None
        """
        self.local_ip = local_ip
        self.local_port = local_port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind((self.local_ip, self.local_port))
        
        self.cipher = Cipher_ECB(key)
        self.lock = threading.Lock()
        
        self.started_stream = False
        self.student_mode = student_mode
        
        self.dest_addr = None
    
    def stop(self) -> None:
        """
        Stops the stream.
        Used outside of the class, by the main thread.

        Returns:
            None
        """
        self.stream = False
        msg = b'STOP000000000000'
        msg = self.cipher.encrypt(msg)
        self.s.sendto(msg, self.dest_addr)
        print('sent stop to', self.dest_addr)
        time.sleep(1)
        self.s.close()
        cv2.destroyAllWindows()
        del self
    
    def start_stream(self) -> None:
        """
        Starts the stream.

        Returns:
            None
        """
        self.stream = True
        
        self.data = b''
        self.thread = threading.Thread(target=self.recv_frames)
        self.thread.start()
        self.show_screenshots()
    
    def recv_frame(self) -> bytes:
        """
        Receives packets from the server.

        Returns:
            data (bytes): The received data.
        """
        packets = []

        self.lock.acquire()
        try:
            first, self.dest_addr = self.s.recvfrom(PACKET_SIZE)
            first = self.cipher.decrypt(first)
            data_len = int.from_bytes(first[:3], 'big')
            num_packets = int.from_bytes(first[3:5], 'big')
            packets.append(first[5:])
            
            for i in range(num_packets-1):
                packet, _ = self.s.recvfrom(PACKET_SIZE)
                packet = self.cipher.decrypt(packet)
                packets.append(packet[5:])
        except OSError:
            pass
            
        self.lock.release()

        packets = sorted(packets, key=lambda x: int.from_bytes(x[:2], 'big'))
        packets = [packet[2:] for packet in packets]
        data = b''.join(packets)
        data = data[:data_len]

        
        return data

    def show_screenshots(self) -> None:
        """
        Shows the screenshot.

        Returns:
            None
        """
                
        state = 1
        screen_name = 'Teacher\'s Screen' if self.student_mode else 'Student\'s Screen'
        thread = threading.Thread(target=self.listen_for_close, args=(screen_name,))
        thread.start()

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
                self.started_stream = True
            except:
                pass

            self.lock.release()
            cv2.waitKey(1)

    def listen_for_close(self, screen_name) -> None:
        if self.student_mode:
            return
        state = 1
        while not self.started_stream:
            time.sleep(0.1)

    
        while True:
            try:
                state = cv2.getWindowProperty(screen_name, 0)#checks if the window is closed
            except cv2.error as e:
                state -= 1
        
            if state < 0:#if the window is closed, stop the stream
                print(state)
                self.stop()
                break
            cv2.waitKey(1)
    
    def recv_frames(self) -> None:
        """
        Continuously receives frames from the server.

        Returns:
            None
        """
        while self.stream:
            try:
                self.data = self.recv_frame()
            except UnboundLocalError:
                pass


def main():
    recv = Receiver('0.0.0.0', 25565, b'1234567890123456')
    recv.start_stream()
    

if __name__ == '__main__':
    main()