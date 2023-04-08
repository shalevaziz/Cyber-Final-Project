import basics
import Freeze
import ScreenShare
import socket
import random


class Client(basics.Encrypted_TCP_Client):
    def __init__(self, ip='127.0.0.1', port=25565):
        super().__init__(ip, port)
        self.freezer = Freeze.Freezer()
    
    def handle_connection(self):
        try:
            super().handle_connection()
            while True:
                msg = self.recv_data().decode()
                if msg == 'FREEZE':
                    self.freezer.freeze()
                elif msg == 'UNFREEZE':
                    self.freezer.unfreeze()
                elif msg == 'GET_MAC':
                    self.send_MAC()
                elif msg == 'SHARE_SCREEN':
                    self.share_screen()
                elif msg == 'TERMINATE':
                    break
        except ConnectionAbortedError:
            basics.logger.log('Connection aborted', self.logger_name)
        except ConnectionResetError:
            basics.logger.log('Connection reset', self.logger_name)
    
    def share_screen(self):
        ip = socket.gethostbyname(socket.gethostname())
        ip = [hex(int(i)) for i in ip.split('.')]
        ip = [i.replace('0x', '').zfill(2) for i in ip]
        ip = ''.join(ip)

        #non reserved ports
        port = random.randint(49152, 65535)
        port = hex(port).replace('0x', '').zfill(4)

        msg = ip + port
        self.send_data(msg)
        print(self.cipher.get_key()[:8])
        transmitter = ScreenShare.ScreenShare_Transmitter('0.0.0.0', int(port, 16), self.cipher.get_key()[:16])
        try:
            transmitter.start_stream()
        except ConnectionAbortedError:
            return
        

        


def main():
    client = Client()
    client.handle_connection()
    
    

if __name__ == '__main__':
    main()