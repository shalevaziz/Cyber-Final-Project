import socket
import cv2
import numpy as np
import time
import threading
import pyautogui
import multiprocessing
RESULUTIONS = (1536, 864)
QUALITY = 95
BYTES = b''
data = b''
PAKCET_SIZE = 512
print(-1%6)
start = time.time()

arr = np.ndarray((6), dtype=object)
arr[0] = b'abc'



class Receiver:
    def __init__(self, local_ip, local_port):
        self.ARR_LEN = 256
        self.local_ip = local_ip
        self.local_port = local_port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind((self.local_ip, self.local_port))
        self.frames = np.ndarray((self.ARR_LEN), dtype=np.ndarray)
        self.packets = multiprocessing.Manager().list()
        self.counter = 0
    
    def start(self):
        """This function starts the reciever.
        """
        self.recv_thread = threading.Thread(target=self.recv_packets)
        self.recv_thread.start()
        self.organize_thread = threading.Thread(target=self.organize_packets)
        self.organize_thread.start()
        self.show_thread = threading.Thread(target=self.show_screenshot)
        self.show_thread.start()

    def organize_packets(self):
        while True:
            if len(self.packets) != 0:
                packet = self.packets.pop(0)
                frame_number = packet[0]
                total_packets = int.from_bytes(packet[1:3], byteorder='big')
                packet_number = int.from_bytes(packet[3:5], byteorder='big')
                if self.frames[frame_number] is None or self.frames[frame_number].size != total_packets:
                        self.frames[frame_number] = np.ndarray((total_packets), dtype=object)

                if frame_number == 255:
                    break

                self.frames[frame_number][packet_number] = packet[5:]
                if len(self.frames[frame_number][self.frames[frame_number] == None]) == 0:
                    print(f'frame {frame_number} is full')
                    self.counter = frame_number
        print(np.where(self.frames[self.counter] == None))

    def recv_packets(self, packets):
        """This function receives packets from the server.

        Args:
            s (socket): The socket to receive data from.
        """
        while True:
            packet, _ = self.s.recvfrom(PAKCET_SIZE)
            packets.append(packet)

           

            

    def show_screenshot(self):
        """This function shows the screenshot.
        """

        while self.frames[self.counter] is None:
            pass
        while True:

            if self.frames[self.counter] is not None and len(self.frames[self.counter][self.frames[self.counter] == None]) == 0:

                frame = b''.join(self.frames[self.counter])
                frame = frame[:frame.find(b'EOF')]
                img = cv2.imdecode(np.frombuffer(frame, np.uint8), cv2.IMREAD_COLOR)
                cv2.imshow(f'ScreenShare{self.counter}', img)
                cv2.waitKey(1)
                self.frames[self.counter] = None


        
def main():
    reciever = Receiver(socket.gethostbyname(socket.gethostname()), 25565)
    multiprocessing.Process(target=reciever.recv_packets, args=(reciever.packets,)).start()
    time.sleep(5)
    print(len(reciever.packets))


if __name__ == '__main__':
    main()

        
    