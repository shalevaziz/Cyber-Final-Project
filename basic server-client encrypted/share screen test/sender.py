import socket
import cv2
import numpy as np
import time
import threading
import pyautogui
from mss import mss
RESULUTIONS = (1536, 864)
QUALITY = 95
frames = []
sct = mss()
PACKET_SIZE = 507
def add_frame():
    global frames
    global mss
    while True:
        frames.append(sct.grab(sct.monitors[1]))

def take_screenshot():
    """This function takes a screenshot of the screen.

    Returns:
        bytes: The screenshot of the screen.
    """
    global frames
    timings = []
    timings.append(time.time())

    while len(frames) == 0:
        pass

    frame = frames.pop(0)
    frame = np.array(frame)
    frame = cv2.resize(frame, RESULUTIONS, interpolation=cv2.INTER_AREA)
    result, frame = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), QUALITY])
    frame = frame.tobytes()
    timings.append(time.time())

    diffs = [timings[i+1]-timings[i] for i in range(len(timings)-1)]
    #print(timings[-1]-timings[0])
    return frame

def split_into_packets(data, frame_index):
    """This function splits the data into packets.

    Args:
        data (bytes): The data to split.

    Returns:
        list: The list of packets.
    """
    to_fill = PACKET_SIZE - (len(data) % PACKET_SIZE)
    finalizer = b'EOF'
    data += finalizer
    to_fill -= len(finalizer)
    data += b'0' * to_fill
    packets = [data[i:i+PACKET_SIZE] for i in range(0, len(data), PACKET_SIZE)]
    for i in range(len(packets)):
        packets[i] = frame_index.to_bytes(1, 'big') + len(packets).to_bytes(2, 'big') + i.to_bytes(2, 'big') + packets[i]
    print(i, len(packets))
    return packets

def send_data(packets, s, address):
    """This function sends data to the client

    Args:
        data (bytes): The data to send.
    """
    for packet in packets:
        s.sendto(packet, address)
        
def main():
    local_ip = '192.168.68.122'
    dest_ip = '192.168.68.113'
    port = 25565

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((local_ip, port))
    start = time.time()
    threading.Thread(target=add_frame).start()

    for i in range(256):
        sct = take_screenshot()
        packets = split_into_packets(sct, i%256)
        send_data(packets, s, (dest_ip, port))
        
    print(time.time()-start)

if __name__ == '__main__':
    main()