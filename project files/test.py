import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
import socket
from threading import Thread
import time
import math
from logger import Logger
import uuid
#import Fernet
from Crypto.Cipher import DES
import os
logger = Logger(debugging_mode=True)

class Useful_Functions:
    @staticmethod
    def split_data(encrypted_msg, packet_size=4096):
        """This function splits the encrypted message into packets of 4096 bytes.
        It also adds a b'END' packet at the end.

        Args:
            encrypted_msg (bytes): The encrypted message.
        
        Returns:
            list: A list of packets.
        """
        packets = []

        for i in range(0, len(encrypted_msg)-packet_size, packet_size):
            packets.append(encrypted_msg[i:i+packet_size])

        data = encrypted_msg[len(encrypted_msg)- len(encrypted_msg)%packet_size:]
        if len(data) > 0:
            packets.append(data)

        return packets
    
    @staticmethod
    def get_MAC_address():
        """This function returns the MAC address of the computer

        Returns:
            str: The MAC address of the computer
        """
        mac = hex(uuid.getnode()).replace('0x', '').upper()
        return ':'.join([mac[i: i + 2] for i in range(0, 11, 2)])

    @staticmethod
    def read_file(file_path: str, chunk_size=4096):
        """This function reads a file and returns its contents

        Args:
            file_path (str): The path to the file

        Returns:
            bytes: The contents of the file
        """
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(chunk_size)
                if not data:
                    break
                yield data
class Cipher:
    """This class is used to encrypt and decrypt messages using AES-EAX mode.
    It also authenticates the messages using HMAC.
    """
    def __init__(self, key=None, bytes=32):
        """This function initializes the cipher.

        Args:
            key (bytes, optional): The key to use. If None, a random key is generated. Defaults to None.
            bytes (int, optional): The number of bytes to use for the key. Defaults to 32.
        """
        self.bytes = bytes
        if key == None:
            self.__key = get_random_bytes(bytes)
        else:
            self.__key = key
        
    def encrypt(self, msg):
        """This function encrypts the message

        Args:
            msg (bytes): The message to encrypt

        Returns:
            bytes: The encrypted message
        """
        cipher = AES.new(self.__key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(msg)
        return cipher.nonce + tag + ciphertext
    
    def decrypt(self, msg):
        """This function decrypts a full message(a message that includes the nonce, tag and ciphertext)

        Args:
            msg (bytes): The message to decrypt

        Returns:
            bytes: The decrypted message
        """
        nonce = msg[:16]
        tag = msg[16:32]
        ciphertext = msg[32:]
        return self.basic_decrypt(ciphertext, nonce, tag)
        
    def basic_decrypt(self, msg, nonce, tag):
        """This function decrypts a message that only includes the ciphertext.
        It also authenticates the message using the nonce and tag.

        Args:
            msg (bytes): The message to decrypt

        Returns:
            bytes: The decrypted message
        """
        cipher = AES.new(self.__key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(msg, tag)
    
    def set_key(self, key):
        """This function sets the key of the cipher.

        Args:
            key (bytes): The key to use.
        """
        if len(key) == self.bytes:
            self.__key = key
    
    def get_key(self):
        """This function returns the key of the cipher.

        Returns:
            bytes: The key of the cipher
        """
        return self.__key

class Cipher_ECB:
    """This class is used to encrypt and decrypt messages using DES mode.
    It also authenticates the messages using HMAC.
    """
    def __init__(self, key=None, bytes=16):
        """This function initializes the cipher.

        Args:
            key (bytes, optional): The key to use. If None, a random key is generated. Defaults to None.
            bytes (int, optional): The number of bytes to use for the key. Defaults to 32.
        """
        self.bytes = bytes
        if key == None:
            self.__key = get_random_bytes(bytes)
        else:
            self.__key = key
        
        self.__cipher = AES.new(self.__key, AES.MODE_ECB)
        
    def encrypt(self, msg):
        """This function encrypts the message

        Args:
            msg (bytes): The message to encrypt

        Returns:
            bytes: The encrypted message
        """
        ciphertext = self.__cipher.encrypt(msg)
        return ciphertext
    
    def decrypt(self, msg):
        """This function decrypts a full message(a message that includes the nonce, tag and ciphertext)

        Args:
            msg (bytes): The message to decrypt

        Returns:
            bytes: The decrypted message
        """
        decrypted = self.__cipher.decrypt(msg)
        
        return decrypted
    
    def set_key(self, key):
        """This function sets the key of the cipher.

        Args:
            key (bytes): The key to use.
        """
        if len(key) == self.bytes:
            self.__key = key
    
    def get_key(self):
        """This function returns the key of the cipher.

        Returns:
            bytes: The key of the cipher
        """
        return self.__key

class Encrypted_TCP_Socket:
    """This class is used to create a TCP socket that uses encryption.
    """
    def __init__(self, ip, port):
        """This function initializes the socket and connects to the server.

        Args:
            ip (string): The IP address of the server.
            port (int): The port of the server.
        """
        self.ip = ip
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.cipher = Cipher()
        
    def handle_connection(self):
        """This function handles the connection to the server.
        """
        raise NotImplementedError("This function must be implemented by a subclass")

    def initiate_encrypted_data_transfer(self):
        """This function initiates the encrypted data transfer.
        """
        raise NotImplementedError("This function must be implemented by a subclass")
    
    def send_data(self, msg, socket = None, packet_size=4096, is_file = False):
        """This function encrypts the message and sends it to the server.

        Args:
            msg (string): The message to send.
            socket (socket): The socket used to send the data.
        """
        if socket == None:
            socket = self.socket
        
        if type(msg) == str:
            msg = msg.encode()

        ciphertext = self.cipher.encrypt(msg)
        packets = Useful_Functions.split_data(ciphertext, packet_size=packet_size)
        first_packet = str(hex(len(packets))).encode().replace(b'0x', b'').zfill(4)
        first_packet += str(hex(packet_size)).encode().replace(b'0x', b'').zfill(4)
        first_packet = self.cipher.encrypt(first_packet)
        socket.send(first_packet)
        
        for packet in packets:
            socket.send(packet)

        response = socket.recv(39)
        response = self.cipher.decrypt(response)
        
        return response == b"SUCCESS"
    
    def decrypt_data(self, data):
        """This function decrypts the data using the AES-256 key.

        Args:
            data (bytes): The data to decrypt.

        Returns:
            bytes: The decrypted data, or False if the decryption failed
        """
        
        msg = self.cipher.decrypt(data)
        
        return msg

    def recv_data(self, socket = None):
        """This function receives data from the server.
        """
        if socket == None:
            socket = self.socket

        full_data = b''
        data = socket.recv(40)
        data = self.decrypt_data(data)
        num_packets = int(data[:4], 16)
        packet_size = int(data[4:8], 16)
        for i in range(num_packets):
            data = socket.recv(packet_size)
            full_data += data

        msg = b'SUCCESS'
        msg = self.cipher.encrypt(msg)
        socket.send(msg)
        
        return self.decrypt_data(full_data)
    
    def send_file(self, path):
        """This function sends a file to the server.

        Args:
            path (string): The path of the file to send.
        """
        file_gen = Useful_Functions.read_file(path, 4064)
        filename = path.split('/')[-1]
        
        file_size = os.path.getsize(path)
        num_packets = math.ceil(file_size / 4064)
        last = file_size % 4064 + 32
        
        print(num_packets, last, filename)
        
        num_packets = num_packets.to_bytes(32, 'big')
        last = last.to_bytes(12, 'big')
        filename = filename.encode()
        
        msg = num_packets + last + filename
        
        self.send_data(msg)
        try:
            for buffer in file_gen:
                buffer = self.cipher.encrypt(buffer)
                print(buffer, len(buffer))
                
                self.socket.sendall(buffer)
        except StopIteration:
            print('sent eof')
        
    def recv_file(self, path):
        msg = self.recv_data()
        
        num_packets = int.from_bytes(msg[:32], 'big')
        last = int.from_bytes(msg[32:44], 'big')
        filename = msg[44:].decode()
        
        print(num_packets, last, filename)
        
        path = os.path.join(path, filename)
        
        with open(path, 'wb') as file:
            for i in range(num_packets-1):
                data = self.socket.recv(4096)
                print(len(data))
                data = self.decrypt_data(data)
                file.write(data)
            data = self.socket.recv(last)
            print(len(data))
            
            data = self.decrypt_data(data)
            file.write(data)


    def __init__(self, local_ip, local_port, dest_ip, dest_port, key):
        """This function initializes the socket and connects to the server.

        Args:
            dest_ip (string): The IP address of the server.
            dest_port (int): The port of the server.
            local_ip (string, optional): The IP address of the local machine. Defaults to None.
            local_port (int, optional): The port of the local machine. Defaults to None.
        """
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.local_ip = local_ip
        self.local_port = local_port
        self.logger_name = "Root"

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((local_ip, local_port))

        self.cipher = Cipher_DES(key)
        
    def send_data(self, msg, packet_size=16384):
        """This function encrypts the message and sends it to the server.

        Args:
            msg (string): The message to send.
            socket (socket): The socket used to send the data.
        """
        print(len(msg))
        if type(msg) == str:
            msg = msg.encode()

        ciphertext = self.cipher.encrypt(msg)
        
        first_packet = str(hex(len(ciphertext))).encode().replace(b'0x', b'').zfill(8)
       
        logger.log_debug(f"Sending First Packet: {first_packet}")

        first_packet = self.cipher.encrypt(first_packet)

        self.socket.sendto(first_packet, (self.dest_ip, self.dest_port))
        
        self.socket.sendto(ciphertext, (self.dest_ip, self.dest_port))
        
        
        data, addr = self.socket.recvfrom(16)
        data = self.cipher.decrypt(data)
        logger.log_debug(f"Received response: {data}", self.logger_name)

    def recv_data(self):
        """This function receives data from the server.
        """
        
        full_data = b''
        data, addr = self.socket.recvfrom(16)
        data = self.cipher.decrypt(data)
        logger.log_debug(f"Received First Packet: {data}", self.logger_name)
        
        packet_size = int(data, 16)
        logger.log_debug(f"Packet Size: {packet_size}", self.logger_name)
        
        
        data, addr = self.socket.recvfrom(packet_size)
        logger.log_debug(f"Received packet: {len(data)}", self.logger_name)
        msg = b'SUCCESS'
        msg = self.cipher.encrypt(msg)
        self.socket.sendto(msg, addr)
        logger.log_debug(f"Sent response: {msg}", self.logger_name)

        return self.cipher.decrypt(data)

class Encrypted_TCP_Client(Encrypted_TCP_Socket):
    def __init__(self, ip='127.0.0.1', port=25565, DES_key=None):
        """This function initializes the socket and connects to the server.

        Args:
            ip (string): The IP address of the server.
            port (int): The port of the server.
        """
        self.logger_name = 'TCP Client'
        logger.create_logger(self.logger_name)
        super().__init__(ip, port)
        if DES_key:
            self.cipher = Cipher_DES(DES_key)

    def handle_connection(self):
        """This function handles the connection to the server.
        """
        self.socket.settimeout(1000)
        self.connected = False
        while not self.connected:
            try:
                self.socket.connect((self.ip, self.port))
                self.connected = True
                print('Connected to server at ' + self.ip + ':' + str(self.port))
                break
            except socket.timeout:
                print('Connection timed out\nTrying again...')
                self.socket.close()
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except ConnectionRefusedError:
                print('Connection refused\nTrying again...')
            except OSError:
                print('Host unreachable\nTrying again...')
            
            time.sleep(10)
                
        self.initiate_encrypted_data_transfer()

    def initiate_encrypted_data_transfer(self):
        """This function initiates the encrypted data transfer.
        """
        logger.log('Initiating encrypted data transfer', log_type='info', logger_name=self.logger_name)
        self.socket.send(b"INITIATE_ENCRYPTED_DATA_TRANSFER")

        logger.log('Sent INITIATE_ENCRYPTED_DATA_TRANSFER', log_type='debug', logger_name=self.logger_name)

        server_public_key = self.socket.recv(4096)
        logger.log('Received server public key', log_type='debug', logger_name=self.logger_name)
        rsa_encryptor = rsa.PublicKey.load_pkcs1(server_public_key)

        msg = self.cipher.get_key()

        logger.log('Generated key', log_type='debug', logger_name=self.logger_name)
        logger.log(f'Key: {self.cipher.get_key()}', log_type='debug', logger_name=self.logger_name)

        msg = rsa.encrypt(msg, rsa_encryptor)
        self.socket.send(msg)
        logger.log('Sent encrypted key', log_type='debug', logger_name=self.logger_name)

        response = self.recv_data(self.socket)
        logger.log(f'Received: {response}', log_type='debug', logger_name=self.logger_name)

        if response == b'ENCRYPTED_DATA_TRANSFER_INITIATED':
            logger.log('Encrypted data transfer initiated', log_type='info', logger_name=self.logger_name)
        else:
            logger.log('Encrypted data transfer failed to initiate. trying again...', log_type='warning', logger_name=self.logger_name)
            self.initiate_encrypted_data_transfer()

    def send_MAC(self):
        """This function sends the MAC address of the client to the server.
        """
        self.send_data(Useful_Functions.get_MAC_address())
        logger.log('Sent MAC address', log_type='debug', logger_name=self.logger_name)

class Encrypted_TCP_Server(Encrypted_TCP_Socket):
    def __init__(self, ip = '0.0.0.0', port = 25565, max_connections = 40):
        """This function initializes the socket and waits for a connection from a client.

        Args:
            ip (string): The IP address of the server.
            port (int): The port of the server.
        """
        global logger
        self.logger_name = 'TCP Server'
        logger.create_logger(self.logger_name)
        self.conns = {}
        

        super().__init__(ip, port)
        self.socket.bind((ip, port))
        logger.log('Server started at ' + ip + ':' + str(port), log_type='info', logger_name=self.logger_name)
        ip = socket.gethostbyname(socket.gethostname())
        print('Server started at ' + ip + ':' + str(port))
    
    def wait_for_connections(self):
        """This function waits for a connection from a client.
        """
        self.socket.listen()
        print('Waiting for connections...')
        while True:
            client_soc, client_address = self.socket.accept()
            print(f'Connection from {client_address[0]}:{client_address[1]}')
            Thread(target=self.handle_connection, args=(client_soc, client_address)).start()

import socket
import random
import time
import threading
#import AppOpener
from pathlib import Path
import os
DOWNLOADS_PATH = str(Path.home() / "Downloads")

class Client(Encrypted_TCP_Client):
    def __init__(self, ip='127.0.0.1', port=25565):
        super().__init__(ip, port)
        #self.freezer = Freeze.Freezer()
    
    def handle_connection(self):
        try:
            super().handle_connection()
            while True:
                msg = self.recv_data().decode()
                print(msg if msg != "PING" else "")
                if msg == 'FREEZE':
                    self.freezer.freeze()
                elif msg == 'UNFREEZE':
                    self.freezer.unfreeze()
                elif msg == 'GET_MAC':
                    self.send_MAC()
                elif msg == 'SHARE_SCREEN':
                    self.share_screen()
                elif msg == 'STOP_SHARE_SCREEN':
                    self.stop_share_screen()
                elif msg == 'VIEW_TEACHER_SCREEN':
                    self.view_teacher_screen()
                elif msg == 'TERMINATE':
                    break
                elif msg == 'PING':
                    self.send_data('PONG')
                elif msg == 'OPEN_URL':
                    AppOpener.AppOpener.open_url(self.recv_data().decode())
                elif msg == 'OPEN_APP':
                    AppOpener.AppOpener.open_app(self.recv_data().decode())
                elif msg == 'ADD_APP':
                    self.add_app(self.recv_data().decode())
                elif msg == 'RECV_FILE':
                    self.recv_file(DOWNLOADS_PATH)
                    
                
        except ConnectionAbortedError:
            logger.log('Connection aborted', self.logger_name)
        except ConnectionResetError:
            logger.log('Connection reset', self.logger_name)
    
    def share_screen(self):
        time.sleep(1)
        dest_port = self.recv_data()
        dest_port = int.from_bytes(dest_port, 'big')
        print(dest_port)
        dest_ip = self.socket.getpeername()[0]
        
        local_port = random.randint(49152, 65535)
        local_ip = self.socket.getsockname()[0]
        
        
        print(self.cipher.get_key()[:8])
        self.sharescreen_transmitter = ScreenShare.Sender(local_ip=local_ip, local_port=local_port, dest_ip=dest_ip, dest_port=dest_port, key = self.cipher.get_key()[:16])
        threading.Thread(target=self.__share_screen).start()
        
    def __share_screen(self):
        try:
            self.sharescreen_transmitter.start_stream()
        except ConnectionAbortedError:
            return
    
    def stop_share_screen(self):
        if "sharescreen_transmitter" in dir(self):
            self.sharescreen_transmitter.stop_stream()
            del self.sharescreen_transmitter

    def add_app(self, path):
        response = AppOpener.AppOpener.add_app(path)
        self.send_data(str(response).encode())
    
    def view_teacher_screen(self):
        key_and_port = self.recv_data()
        key = key_and_port[:16]
        port = int.from_bytes(key_and_port[16:], 'big')
        
        reciever = ScreenShare.Receiver('0.0.0.0', port, key, student_mode=True)
        threading.Thread(target=reciever.start_stream).start()

    def recv_file(self, path):
        super().recv_file(path)
        #os.startfile(path)

import keyboard
import mouse
import time
from threading import Thread

class Freezer:
    def __init__(self):
        """Initializes the Freezer object."""
        self.frozen = False
    
    def freeze(self):
        """Freezes the PC by blocking all keyboard input and starting a thread to freeze the mouse."""
        for i in range(150):
            keyboard.block_key(i)
        
        self.frozen = True
        t = Thread(target=self.freeze_mouse)
        t.start()

    def freeze_mouse(self):
        """Freezes the mouse by continuously moving it to the same position."""
        while self.frozen:
            mouse.move(1, 1, absolute=True, duration=0) 
    
    def unfreeze(self):
        """Unfreezes the PC by unblocking all keyboard input."""
        keyboard.unhook_all()
        self.frozen = False
    
    def is_frozen(self):
        """Returns whether the PC is currently frozen or not.

        Returns:
            bool: True if the PC is frozen, False if not.
        """
        return self.frozen

import tkinter as tk
from tkinter import font, messagebox, filedialog
from PIL import Image, ImageTk
import json
from threading import Thread
import time
import os
from hashlib import sha256

class Main_Window(tk.Tk):
    def __init__(self, server):
        super().__init__()
        self.geometry("1200x800")
        self.title("First Setup")
        self.resizable(False, False)
        
        self.frames = {}
        self.load_frames()
        
        self.server = server

        self.current_frame_name = 'main'
        self.current_frame = self.frames[self.current_frame_name](self)
        self.current_frame.pack(anchor='nw', fill='both', expand=True)
        

        
        self.mainloop()
    
    def load_frames(self):
        self.frames['main'] = Main_Frame
        self.frames['edit'] = Edit_Frame
    
    def show_frame(self, frame):
        if frame == 'edit':
            if not self.check_password():
                return
        self.current_frame.destroy()
        self.current_frame_name = frame
        self.current_frame = self.frames[self.current_frame_name](self)
        self.current_frame.pack(anchor='nw', fill='both', expand=True)
        self.current_frame.load_pcs()
    
    def check_password(self):
        if os.path.isfile('password.txt'):
            with open('password.txt', 'rb') as f:
                password = f.read()
                if password != '':
                    user_input = tk.simpledialog.askstring('Password', 'Enter password', show='*').encode()
                    user_input = sha256(user_input).digest()
                    user_input = sha256(user_input).digest()
                    if  password == user_input:
                        return True
                    else:
                        messagebox.showerror('Error', 'Wrong password')
                        return False
                
        
        user_input = tk.simpledialog.askstring('Create Password', 'No Password file was found. Please create a password.', show='*').encode()
        user_input = sha256(user_input).digest()
        user_input = sha256(user_input).digest()
        with open('password.txt', 'wb') as f:
            f.write(user_input)
        return True

class Window(tk.Frame):
    def __init__(self, master=None):
        global PC_ICON_ONLINE, PC_ICON_OFFLINE, X_ICON
        self.master = master
        self.master.geometry("1200x800")
        self.master.title("First Setup")
        self.master.resizable(False, False)
        self.pcs_pos = {}
        self.pcs = {}
        super().__init__(master, width = 1200, height = 800)
        
        PC_ICON_ONLINE = ImageTk.PhotoImage(Image.open(r"icons/pc_icon_online.png").resize((100, 100)))
        PC_ICON_OFFLINE = ImageTk.PhotoImage(Image.open(r"icons/pc_icon_offline.png").resize((100, 100)))
        X_ICON = ImageTk.PhotoImage(Image.open(r"icons/x_icon.png").resize((20, 20)))
        
        Thread(target=self.update_icons).start()
    
    def load_pcs(self):
        for pc in self.pcs.values():
            if pc is not None:
                pc.destroy()

        self.pcs = {}
        connected_pcs = self.master.server.conns.keys()
        with open('locations.json', 'r+') as f:
            self.pcs_pos = json.load(f)
        
        for pc in self.pcs_pos.items():
            self.pcs[pc[0]] = self.create_PCIcon(pc[0], pc[1], pc[0] in connected_pcs)
    
    def create_PCIcon(self, mac, pos = (0,0), online = True):
        raise NotImplementedError('This function is not implemented in the base class')

    def update_icons(self):
        while self.winfo_exists():
            self.load_pcs()
            self.master.server.new_connection = False
            while not self.master.server.new_connection and self.winfo_exists():
                time.sleep(3)

class Main_Frame(Window):
    def __init__(self, master):
        super().__init__(master)
        self.create_menubar()

        self.master.server.allow_new_connections = False

        self.bind('<Button-1>', lambda event: self.dropdown.place_forget())

    def create_dropdown(self, mac):
        self.dropdown = DropDownMenu(self, mac)

    def create_menubar(self):
        self.menubar = tk.Menu(self)
        actions_menu = tk.Menu(self.menubar, tearoff = 0)
        actions_menu.add_command(label = 'Edit', command = self.show_edit_frame)
        actions_menu.add_command(label = 'Stream Screen', command = lambda: self.master.server.stream_screen())
        actions_menu.add_command(label = 'Send File', command = self.send_file)
        
        self.menubar.add_cascade(label = 'Actions', menu = actions_menu)
        
        self.master.config(menu = self.menubar)
        
    def assign_dropdown(self, mac):
        if not self.pcs[mac].online:
            return
        self.create_dropdown(mac)
        pos = self.pcs_pos[mac]
        self.dropdown.place(x = pos[0]+10, y = pos[1]+130)

        self.dropdown.tkraise()
    
    def create_PCIcon(self, mac, pos = (0,0), online = True):
        pc_icon = PCIcon_View_Mode(self, mac, pos, online)
        self.pcs_pos[mac] = pos
        return pc_icon

    def show_edit_frame(self):
        if self.master.server.streaming_screen:
            messagebox.showerror('Error', 'You cannot edit the locations while streaming the screen')
            return
        
        self.master.show_frame('edit')
    
    def stream_screen(self):
        if self.master.server.streaming_screen:
            messagebox.showerror('Error', 'You are already streaming the screen')
            return
        
        self.master.server.stream_screen()
    
    def send_file(self):
        file_path = filedialog.askopenfilename()
        if file_path == '':
            return
        self.master.server.send_file_to_all(file_path)

class Edit_Frame(Window):
    def __init__(self, master=None):
        super().__init__(master)
        self.create_done_button()
        self.load_pcs()
        
        self.master.server.allow_new_connections = True
    
    def create_done_button(self):
        self.done_button = tk.Button(self, text = 'Save', command = lambda: self.master.show_frame('main'))
        self.done_button.place(x = 1100, y = 700)

    def create_PCIcon(self, mac, pos = (0,0), online = True):
        pc_icon = PCIcon_Edit_Mode(self, mac, pos, online)
        self.pcs_pos[mac] = pos
        return pc_icon
    
    def change_location(self, mac, pos):
        self.pcs_pos[mac] = tuple(pos)
        with open('locations.json', 'w') as f:
            json.dump(self.pcs_pos, f)

    def remove_pc(self, mac):
        self.pcs_pos.pop(mac)
        with open('locations.json', 'w') as f:
            json.dump(self.pcs_pos, f)

class Basic_PCIcon(tk.Canvas):
    def __init__(self, master, mac, pos, online = True):
        super().__init__(master, width=130, height=130)
        
        self.mac = mac
        self.online = online
        self.pos = pos

        self.place(x = self.pos[0], y = self.pos[1])
        
        self.create_label()
        self.change_icon()

    def create_label(self):
        self.label = tk.Label(self, text = self.mac)
        self.label.place(x = 0, y = 110)

    def change_icon(self):
        if self.online:
            self.create_image(10,5, anchor = tk.NW, image = PC_ICON_ONLINE)
        else:
            self.create_image(10,5, anchor = tk.NW, image = PC_ICON_OFFLINE)

class PCIcon_Edit_Mode(Basic_PCIcon):
    def __init__(self, master, mac, pos, online = True):
        super().__init__(master, mac, pos, online = online)
        
        self.create_delete_button()
        
        self.make_draggable()
    
    def create_delete_button(self):
        self.delete_button = tk.Label(self, image = X_ICON)
        self.delete_button.place(x = 110, y = 0)
        self.delete_button.bind("<Button-1>", lambda event: self.delete_pc())

    def make_draggable(self):
        self.bind("<Button-1>", self.on_click)
        self.bind("<B1-Motion>", self.on_drag)
        self.bind("<ButtonRelease-1>", self.on_release)
    
    def on_click(self, event):
        self.start_x = event.x
        self.start_y = event.y
    
    def on_drag(self, event):
        x = self.winfo_x() - self.start_x + event.x
        y = self.winfo_y() - self.start_y + event.y
        self.place(x = x, y = y)
        self.pos = (x, y)
    
    def on_release(self, event):
        self.master.change_location(self.mac, self.pos)
    
    def delete_pc(self):
        response = messagebox.askquestion("Delete PC", "Are you sure you want to delete this PC?", icon = 'warning')
        if response == 'yes':
            self.master.remove_pc(self.mac)
            super().destroy()

class PCIcon_View_Mode(Basic_PCIcon):
    def __init__(self, master, mac, pos, online = True):
        super().__init__(master, mac, pos, online = online)
        self.bind("<Button-1>", self.on_click)

    def on_click(self, event):
        x = self.winfo_x()
        y = self.winfo_y()
        self.master.assign_dropdown(self.mac)

class DropDownMenu(tk.Listbox):
    def __init__(self, master, mac):
        text_font = font.Font(family = "Calibri", size = 13)
        super().__init__(master, width = 11, height = 3, selectmode = tk.SINGLE, font=text_font)
        self.mac = mac

        self.is_frozen = self.master.master.server.conns[self.mac].is_frozen
        
        self.add_options()
    
        self.bind("<<ListboxSelect>>", self.on_select)

    
    def add_options(self):
        self.insert(0,"See Screen")
        if self.is_frozen:
            self.insert(1,"Unfreeze")
        else:
            self.insert(1,"Freeze")
    
    def on_select(self, event):
        selection = self.curselection()[0]
        
        if selection == 0:#See Screen
            Thread(target=self.master.master.server.conns[self.mac].view_screen()).start()
            
        elif selection == 1:#Freeze/Unfreeze
            if self.is_frozen:
                self.master.master.server.conns[self.mac].unfreeze()
                self.is_frozen = False
                self.delete(1)
                self.insert(1,"Freeze")
            else:
                self.master.master.server.conns[self.mac].freeze()
                self.is_frozen = True
                self.delete(1)
                self.insert(1,"Unfreeze")
    
    
    def get_mac(self):
        return self.mac

import logging
from logging.handlers import SocketHandler

class Logger:
    def __init__(self, debugging_mode = False, logger_name = 'Root'):
        self.root_logger = logging.getLogger(logger_name)
        self.root_logger.setLevel(1)  
        self.socket_handler = SocketHandler('127.0.0.1', 19996) 
        self.root_logger.addHandler(self.socket_handler)
        self.root_logger.info('logger started')
        self.loggers = {'Root':self.root_logger}
        self.debugging_mode = debugging_mode
    
    def create_logger(self, name:str, parent_logger = 'Root'):
        if name not in self.loggers and parent_logger in self.loggers:
            self.loggers[name] = self.loggers[parent_logger].getChild(name)
    
    def log_info(self, log:str, logger_name = 'Root'):
        if logger_name in self.loggers:
            self.loggers[logger_name].info(log)
    
    def log_warning(self, log:str, logger_name = 'Root'):
        if logger_name in self.loggers:
            self.loggers[logger_name].warning(log)
    
    def log_error(self, log:str, logger_name = 'Root'):
        if logger_name in self.loggers:
            self.loggers[logger_name].error(log)
    
    def log_critical(self, log:str, logger_name = 'Root'):
        if logger_name in self.loggers:
            self.loggers[logger_name].critical(log)
    
    def log_debug(self, log:str, logger_name = 'Root'):
        if logger_name in self.loggers and self.debugging_mode:
            self.loggers[logger_name].debug(log)
    
    def log(self, log:str, log_type:str = 'info', logger_name = 'Root'):
        log_type = log_type.lower()
        if log_type == 'critical':
            self.log_critical(log=log, logger_name=logger_name)
        if log_type == 'error':
            self.log_error(log=log, logger_name=logger_name)
        if log_type == 'warning':
            self.log_warning(log=log, logger_name=logger_name)
        if log_type == 'info':
            self.log_info(log=log, logger_name=logger_name)
        if log_type == 'debug':
            self.log_debug(log=log, logger_name=logger_name)

import cv2
import numpy as np
import socket
import pyautogui
import threading
#from basics import Cipher_ECB
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

from threading import Thread
import rsa
import json
import time
from Crypto.Random import get_random_bytes
import socket
import random

BROADCAST_PORT = 25566

class Server(Encrypted_TCP_Server):
    def __init__(self, ip='0.0.0.0', port=25565):
        super().__init__(ip, port)
        self.allow_new_connections = False
        self.new_connection = False
        self.temp_conns = {}
        
        self.streaming_screen = False
                
        #Thread(target=self.ping_all).start()

    def get_allowed_pcs(self):
        with open('locations.json', 'r+') as f:
            self.allowed_MACs = [a[0] for a in json.load(f).items()]
    
    def handle_connection(self, client_soc, client_address):
        try:
            self.temp_conns[client_address] = Client_Socket(self.ip, self.port, client_soc)
            if not self.temp_conns[client_address].handle_connection():
                self.temp_conns.pop(client_address)
                return
            mac = self.temp_conns[client_address].get_MAC()
            print(mac)
            
            self.get_allowed_pcs()
            
            if mac in self.allowed_MACs:
                self.conns[mac] = self.temp_conns.pop(client_address)
                print(f'Connection with {client_address} established')
                print(f'mac: {mac}')
                self.new_connection = True
            elif self.allow_new_connections:
                self.conns[mac] = self.temp_conns.pop(client_address)
                
                with open('locations.json', 'r+') as f:
                    pcs = json.load(f)
                
                with open('locations.json', 'w+') as f:
                    pcs[mac] = [0, 0]
                    json.dump(pcs, f)

                self.new_connection = True
            else:
                self.temp_conns[client_address].terminate()
                self.temp_conns.pop(client_address)
                print(f'Connection with {client_address} not allowed')
                print(f'mac: {mac}')
                print(f'allowed macs: {self.allowed_MACs}')
                print(self.allow_new_connections)
        except ConnectionAbortedError:
            logger.log(f'Connection with {client_address} aborted', self.logger_name)
            self.conns.pop(client_address)
        except ConnectionResetError:
            logger.log(f'Connection with {client_address} reset', self.logger_name)
            self.conns.pop(client_address)
    
    def ping_all(self):
        while True:
            for mac in self.conns.keys():
                Thread(target=self.ping_one, args=(mac,)).start()
            time.sleep(10)
    
    def ping_one(self, mac):
        
        if self.conns[mac] is None:
            return
        self.conns[mac].settimeout(5)
        
        try:
            alive = self.conns[mac].ping()
        except ValueError:
            alive = False
            print('ValueError')
            
        if not alive:
            print(f'{mac} is not alive')
            try:
                self.conns.pop(mac)
            except KeyError:
                pass
        
        self.new_connection = True
        
        return alive

    def add_app(self, path):
        failed = []
        for client in self.conns.items():
            if not client[1].add_app(path):
                failed.append(client[0])
        return failed
    
    def stream_screen(self):
        key = get_random_bytes(16)
        for conn in self.conns.values():
            conn.share_screen(key, BROADCAST_PORT)
        
        self.streamer = ScreenShare.MultiSender(BROADCAST_PORT, BROADCAST_PORT, key)
        time.sleep(1)
        Thread(target=self.streamer.start_stream).start()
        self.streaming_screen = True
        
    def stop_streaming_screen(self):
        self.streamer.stop_stream()
        del self.streamer
        self.streaming_screen = False
    
    def send_file_to_all(self, path):
        print(self.conns)
        for conn in self.conns.values():
            Thread(target=conn.send_file, args=(path,)).start()

class Client_Socket(Encrypted_TCP_Socket):
    def __init__(self, ip, port, client_soc):
        super().__init__(ip, port)
        self.socket = client_soc
        self.client_addr = self.socket.getpeername()
        (self.public_key, self.private_key) = rsa.newkeys(1024)
        self.is_frozen = False
        
    def handle_connection(self):
        """This function handles the connection to the server.
        """
        encrypted_communication = self.initiate_encrypted_data_transfer()
        if not encrypted_communication:
            self.terminate()
            return False
        return True

    def initiate_encrypted_data_transfer(self):
        """This function initiates the encrypted data transfer.
        """
        response = self.socket.recv(4096)
        if response == b'INITIATE_ENCRYPTED_DATA_TRANSFER':
            self.socket.send(self.public_key.save_pkcs1())
            AES_key = self.socket.recv(4096)
            if AES_key == b'':
                return False
            
            AES_key = rsa.decrypt(AES_key, self.private_key)
            self.key = AES_key
            self.cipher = Cipher(AES_key)

            self.send_data(b"ENCRYPTED_DATA_TRANSFER_INITIATED")
            return True
        else:
            return self.initiate_encrypted_data_transfer()
    
    def settimeout(self, timeout):
        self.socket.settimeout(timeout)
        
    def get_MAC(self):
        """This function gets the MAC address of the client.

        Args:
            client_soc (socket): The socket of the client.

        Returns:
            string: The MAC address of the client.
        """
        self.send_data("GET_MAC")
        MAC = self.recv_data().decode()
        if len(MAC.split(':')) == 6:
            return MAC
        
        else:
            return self.get_MAC()
    
    def send_data(self, msg, packet_size=4096):
        return super().send_data(msg = msg, socket = self.socket, packet_size = packet_size)
    
    def recv_data(self):
        return super().recv_data(self.socket)
    
    def view_screen(self):
        self.send_data('SHARE_SCREEN')
        port = random.randint(49152, 65535)
        self.send_data(port.to_bytes(16, 'big'))
        
        receiver = ScreenShare.Receiver(self.ip, port, self.cipher.get_key()[:16])
        Thread(target = receiver.start_stream).start()
    
    def freeze(self):
        self.send_data('FREEZE')
        self.is_frozen = True
    
    def unfreeze(self):
        self.send_data('UNFREEZE')
        self.is_frozen = False
    
    def terminate(self):
        self.send_data('TERMINATE')
        self.socket.close()
    
    def ping(self):
        self.socket.settimeout(10)
        try:
            self.send_data('PING')
            response = self.recv_data()
            return response == b'PONG'
        except (ConnectionResetError, BrokenPipeError, TimeoutError):
            return False
        
    def open_URL(self, URL):
        self.send_data('OPEN_URL')
        self.send_data(URL.encode())
    
    def open_App(self, app):
        self.send_data('OPEN_APP')
        self.send_data(app.encode())
    
    def add_app(self, path):
        self.send_data('ADD_APP')
        self.send_data(path.encode())
    
    def share_screen(self, key, port):
        self.send_data('VIEW_TEACHER_SCREEN')
        self.send_data(b''.join([key, port.to_bytes(16, 'big')]))
    
    def send_file(self, path):
        self.send_data('RECV_FILE')
        return super().send_file(path)
            
