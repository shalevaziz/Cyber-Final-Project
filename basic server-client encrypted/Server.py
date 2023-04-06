import basics

class Server(basics.Encrypted_TCP_Server):
    def __init__(self, ip='0.0.0.0', port=25565):
        super().__init__(ip, port)
        self.clients = {}
    
    def handle_connection(self, client_soc, client_address):
        super().handle_connection(client_soc, client_address)
        while True:
            msg = input('Data: ')
            self.send_data(msg, client_socket=client_soc)

def main():
    server = Server()
    server.wait_for_connections()

if __name__ == '__main__':
    main()