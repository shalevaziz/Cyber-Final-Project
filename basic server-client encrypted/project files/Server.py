import basics
import ScreenShare
import socket
import random
import GUI
from threading import Thread
import rsa
import json

class Server(basics.Encrypted_TCP_Server):
    def __init__(self, ip='0.0.0.0', port=25565):
        super().__init__(ip, port)
        self.allow_new_connections = False

    def get_allowed_pcs(self):
        with open('locations.json', 'r+') as f:
            self.allowed_MACs = [a[0] for a in json.load(f).items()]
    
    def handle_connection(self, client_soc, client_address):
        try:
            self.conns[client_address] = Client_Socket(self.ip, self.port, client_soc)
            self.conns[client_address].handle_connection()
            mac = self.conns[client_address].get_MAC()
            
            self.get_allowed_pcs()
            
            if mac in self.allowed_MACs:
                self.conns[mac] = self.conns.pop(client_address)
                print(f'Connection with {client_address} established')
                print(f'mac: {mac}')
            elif self.allow_new_connections:
                self.conns[mac] = self.conns.pop(client_address)
                
                with open('locations.json', 'r+') as f:
                    pcs = json.load(f)
                
                with open('locations.json', 'w+') as f:
                    pcs[mac] = [0, 0]
                    json.dump(pcs, f)

                self.new_connenction = True
            else:
                self.conns[client_address].terminate()
                self.conns.pop(client_address)
                print(f'Connection with {client_address} not allowed')
                print(f'mac: {mac}')
                print(f'allowed macs: {self.allowed_MACs}')
        except ConnectionAbortedError:
            basics.logger.log(f'Connection with {client_address} aborted', self.logger_name)
            self.conns.pop(client_address)
        except ConnectionResetError:
            basics.logger.log(f'Connection with {client_address} reset', self.logger_name)
            self.conns.pop(client_address)
    
class Client_Socket(basics.Encrypted_TCP_Socket):
    def __init__(self, ip, port, client_soc):
        super().__init__(ip, port)
        self.socket = client_soc
        self.client_addr = self.socket.getpeername()
        (self.public_key, self.private_key) = rsa.newkeys(1024)
        
    
    def handle_connection(self):
        """This function handles the connection to the server.
        """
        encrypted_communication = self.initiate_encrypted_data_transfer()
        
        if not encrypted_communication:
            self.socket.send(b'TERMINATE')
            self.socket.close()
            self.conns.pop(self.client_addr)
            return

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
            self.cipher = basics.Cipher(AES_key)

            self.send_data(b"ENCRYPTED_DATA_TRANSFER_INITIATED")
            return True
        else:
            return self.initiate_encrypted_data_transfer()
    
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
    
    def share_screen(self):
        port = random.randint(49152, 65535)
        self.send_data(port.to_bytes(16, 'big'))
        
        receiver = ScreenShare.Receiver(self.ip, port, self.cipher.get_key()[:16])
        receiver.start_stream()
    
    def freeze(self):
        self.send_data('FREEZE')
    
    def unfreeze(self):
        self.send_data('UNFREEZE')
    
    def terminate(self):
        self.send_data('TERMINATE')
        self.socket.close()
        
def main():
    server = Server()
    Thread(target=server.wait_for_connections).start()
    gui = GUI.Main_Window(server)
    
    

if __name__ == '__main__':
    main()