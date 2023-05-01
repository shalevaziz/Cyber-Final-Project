import basics
import ScreenShare
import socket
class Server(basics.Encrypted_TCP_Server):
    def __init__(self, ip='0.0.0.0', port=25565):
        super().__init__(ip, port)
        print(f'Server started on {socket.gethostbyname(socket.gethostname())}:{port}')
    
    def handle_connection(self, client_soc, client_address):
        try:
            super().handle_connection(client_soc, client_address)
            while True:
                msg = input(f'Data {client_address}: ')
                self.send_data(msg, client_socket=client_soc)
                if msg == 'SHARE_SCREEN':
                    self.share_screen(client_soc)
        except ConnectionAbortedError:
            basics.logger.log(f'Connection with {client_address} aborted', self.logger_name)
            self.conns.pop(client_address)
        except ConnectionResetError:
            basics.logger.log(f'Connection with {client_address} reset', self.logger_name)
            self.conns.pop(client_address)
    
    def share_screen(self, client_soc):
        ip_and_port = self.recv_data(client_socket=client_soc).decode()
        ip = ip_and_port[:8]
        ip = [str(int(i, 16)) for i in [ip[:2], ip[2:4], ip[4:6], ip[6:]]]
        ip = '.'.join(ip)
        port = int(ip_and_port[8:], 16)

        print(self.cipher.get_key()[:8])
        receiver = ScreenShare.ScreenShare_Viewer(ip, port, self.cipher.get_key()[:16])
        receiver.start_stream()

def main():
    """server = Server()
    server.wait_for_connections()"""
    """server = Server()
    server.wait_for_connections()"""
    viewer = ScreenShare.ScreenShare_Viewer('127.0.0.1', 25565, b'0123456789012345')
    viewer.start_stream()

if __name__ == '__main__':
    main()