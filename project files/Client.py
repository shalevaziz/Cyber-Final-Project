import basics
#import Freeze
import ScreenShare
import socket
import random
import time
#import AppOpener
class Client(basics.Encrypted_TCP_Client):
    def __init__(self, ip='127.0.0.1', port=25565):
        super().__init__(ip, port)
        #self.freezer = Freeze.Freezer()
    
    def handle_connection(self):
        try:
            super().handle_connection()
            while True:
                msg = self.recv_data().decode()
                print(msg)
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
                
        except ConnectionAbortedError:
            basics.logger.log('Connection aborted', self.logger_name)
        except ConnectionResetError:
            basics.logger.log('Connection reset', self.logger_name)
    
    def share_screen(self):
        time.sleep(1)
        dest_port = self.recv_data()
        dest_port = int.from_bytes(dest_port, 'big')
        dest_ip = self.socket.getpeername()[0]
        
        local_port = random.randint(49152, 65535)
        local_ip = self.socket.getsockname()[0]
        
        
        print(self.cipher.get_key()[:8])
        self.sharescreen_transmitter = ScreenShare.Sender(local_ip=local_ip, local_port=local_port, dest_ip=dest_ip, dest_port=dest_port, key = self.cipher.get_key()[:16])
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

        


def main():
    client = Client('192.168.68.115', 25565)
    client.handle_connection()
    
    

if __name__ == '__main__':
    main()