import basics
import Freeze

class Client(basics.Encrypted_TCP_Client):
    def __init__(self, ip='127.0.0.1', port=25565):
        super().__init__(ip, port)
        self.freezer = Freeze.Freezer()
    
    def handle_connection(self):
        super().handle_connection()
        while True:
            msg = self.recv_data()
            if msg == b'FREEZE':
                self.freezer.freeze()
            elif msg == b'UNFREEZE':
                self.freezer.unfreeze()
            elif msg == b'GET_MAC':
                self.send_MAC()
            elif msg == b'TERMINATE':
                break
        
def main():
    client = Client()
    client.handle_connection()

if __name__ == '__main__':
    main()