import basics
import ScreenShare
import socket
import random
import GUI
from threading import Thread
import rsa
import json
import time
from Crypto.Random import get_random_bytes
BROADCAST_PORT = 25566

class Server(basics.Encrypted_TCP_Server):
    """This class is the server. This class is used to manage the connections between the teacher and the students.
    this class runs on the teacher's computer.
    """
    def __init__(self, ip='0.0.0.0', port=25565):
        """This function initializes the server.

        Args:
            ip (str, optional): The ip to run the server on. Defaults to '0.0.0.0'.
            port (int, optional): The port to run the server on. Defaults to 25565.
        """
        super().__init__(ip, port)
        self.allow_new_connections = False
        self.new_connection = False
        self.temp_conns = {}
        
        self.streaming_screen = False
                
        Thread(target=self.ping_all).start()

    def get_allowed_pcs(self):
        """Gets the allowed pcs from the locations.json file.
        """
        with open('locations.json', 'r+') as f:
            self.allowed_MACs = [a[0] for a in json.load(f).items()]
    
    def handle_connection(self, client_soc, client_address):
        """Handles the connection with the client.

        Args:
            client_soc (socket): The socket of the client.
            client_address (tuple): The address of the client.
        """
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
            basics.logger.log(f'Connection with {client_address} aborted', self.logger_name)
            self.conns.pop(client_address)
        except ConnectionResetError:
            basics.logger.log(f'Connection with {client_address} reset', self.logger_name)
            self.conns.pop(client_address)
    
    def ping_all(self):
        """This function pings all the connected clients every 10 seconds.
        """
        while True:
            for mac in self.conns.keys():
                Thread(target=self.ping_one, args=(mac,)).start()
            time.sleep(10)
    
    def ping_one(self, mac):
        """This function pings one client.

        Args:
            mac (str): The mac address of the client.

        Returns:
            bool: True if the client is alive, False otherwise.
        """
        
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
    
    def stream_screen(self):
        """This function starts streaming the screen to all the connected clients.
        """
        key = get_random_bytes(16)
        for conn in self.conns.values():
            conn.share_screen(key, BROADCAST_PORT)
        
        self.streamer = ScreenShare.MultiSender(BROADCAST_PORT, BROADCAST_PORT, key)
        time.sleep(1)
        Thread(target=self.streamer.start_stream).start()
        self.streaming_screen = True
        
    def stop_streaming_screen(self):
        """This function stops streaming the screen to all the connected clients.
        """
        self.streamer.stop_stream()
        del self.streamer
        self.streaming_screen = False
    
    def send_file_to_all(self, path):
        """This function sends a file to all the connected clients.
        
        Args:
            path (str): The path of the file to send.
        """
        for conn in self.conns.values():
            Thread(target=conn.send_file, args=(path,)).start()
        
    def open_URL_in_all(self, URL):
        """This function opens a URL in all the connected clients.
        
        Args:
            URL (str): The URL to open.
        """
        for conn in self.conns.values():
            Thread(target=conn.open_URL, args=(URL,)).start()

class Client_Socket(basics.Encrypted_TCP_Socket):
    """This class represents a client socket. It is used to communicate with the one client, from the server.
    """
    def __init__(self, ip, port, client_soc):
        """This function initializes the client socket.
        
        Args:
            ip (str): The ip of the server.
            port (int): The port of the server.
            client_soc (socket): The socket of the client.
        """
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
        msg = self.socket.recv(4096)
        if msg == b'INITIATE_ENCRYPTED_DATA_TRANSFER':
            
            self.socket.send(self.public_key.save_pkcs1())#send public key
            
            AES_key = self.socket.recv(4096)#receive encrypted AES key
            if AES_key == b'':
                return False
            
            #decrypt AES key and create cipher object
            AES_key = rsa.decrypt(AES_key, self.private_key)
            self.key = AES_key
            self.cipher = basics.Cipher(AES_key)

            self.send_data(b"ENCRYPTED_DATA_TRANSFER_INITIATED")#send confirmation
            return True
        else:
            return self.initiate_encrypted_data_transfer()#try again
    
    def settimeout(self, timeout):
        """This function sets the timeout of the socket.
        
        Args:
            timeout (int): The timeout in seconds.
        """
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
        """This function sends data to the client.
        
        Args:
            msg (bytes): The data to send.
            packet_size (int): The packet size to use.
        
        Returns:
            bool: True if the data was sent successfully, False otherwise.
        """
        return super().send_data(msg = msg, socket = self.socket, packet_size = packet_size)
    
    def recv_data(self):
        """This function receives data from the client.

        Returns:
            bytes: The data received.
        """
        return super().recv_data(self.socket)
    
    def view_screen(self):
        """This function views the screen of the client.
        """
        self.send_data('SHARE_SCREEN')
        port = random.randint(49152, 65535)
        self.send_data(port.to_bytes(16, 'big'))
        
        receiver = ScreenShare.Receiver(self.ip, port, self.cipher.get_key()[:16])
        Thread(target = receiver.start_stream).start()
    
    def freeze(self):
        """This function freezes the screen of the client.
        """
        self.send_data('FREEZE')
        self.is_frozen = True
    
    def unfreeze(self):
        """This function unfreezes the screen of the client.
        """
        self.send_data('UNFREEZE')
        self.is_frozen = False
    
    def terminate(self):
        """This function terminates the connection to the client.
        """
        self.send_data('TERMINATE')
        self.socket.close()
    
    def ping(self):
        """This function pings the client.

        Returns:
            bool: True if the client is connected, False otherwise.
        """        
        self.socket.settimeout(10)
        try:
            self.send_data('PING')
            response = self.recv_data()
            return response == b'PONG'
        except (ConnectionResetError, BrokenPipeError, TimeoutError):
            return False
        
    def open_URL(self, URL):
        """This function opens a URL in the client.
        
        Args:
            URL (str): The URL to open.
        """
        self.send_data('OPEN_URL')
        self.send_data(URL.encode())
        self.send_data('ADD_APP')
        self.send_data(path.encode())
    
    def share_screen(self, key, port):
        """This function shares the screen of the client with the teacher.
        
        Args:
            key (bytes): The key to use.
            port (int): The port to use.
        """
        self.send_data('VIEW_TEACHER_SCREEN')
        self.send_data(b''.join([key, port.to_bytes(16, 'big')]))
    
    def send_file(self, path):
        """This function sends a file to the client.

        Args:
            path (str): The path of the file to send.

        Returns:
            bool: True if the file was sent successfully, False otherwise.
        """
        self.send_data('RECV_FILE')
        return super().send_file(path)

def main():
    server = Server()
    Thread(target=server.wait_for_connections).start()
    gui = GUI.Main_Window(server)
    
    

if __name__ == '__main__':
    main()