class Server(Encrypted_TCP_Server):
    """
    
    """
    def __init__(self, ip, port):
        pass

    def get_allowed_pcs(self):
        pass

    def handle_connection(self, client_soc, client_address):
        pass

    def ping_all(self):
        pass

    def ping_one(self, mac):
        pass

    def add_app(self, path):
        pass

    def stream_screen(self):
        pass

    def stop_streaming_screen(self):
        pass

    def send_file_to_all(self, path):
        pass


class Client_Socket(Encrypted_TCP_Socket):
    """
    
    """
    def __init__(self, ip, port, client_soc):
        pass

    def handle_connection(self):
        """
        This function handles the connection to the server.
        
        """
        pass

    def initiate_encrypted_data_transfer(self):
        """
        This function initiates the encrypted data transfer.
        
        """
        pass

    def settimeout(self, timeout):
        pass

    def get_MAC(self):
        """
        This function gets the MAC address of the client.

Args:
    client_soc (socket): The socket of the client.

Returns:
    string: The MAC address of the client.
        """
        pass

    def send_data(self, msg, packet_size):
        pass

    def recv_data(self):
        pass

    def view_screen(self):
        pass

    def freeze(self):
        pass

    def unfreeze(self):
        pass

    def terminate(self):
        pass

    def ping(self):
        pass

    def open_URL(self, URL):
        pass

    def open_App(self, app):
        pass

    def add_app(self, path):
        pass

    def share_screen(self, key, port):
        pass

    def send_file(self, path):
        pass


class Client(Encrypted_TCP_Client):
    """
    
    """
    def __init__(self, ip, port):
        pass

    def handle_connection(self):
        pass

    def share_screen(self):
        pass

    def __share_screen(self):
        pass

    def stop_share_screen(self):
        pass

    def add_app(self, path):
        pass

    def view_teacher_screen(self):
        pass

    def recv_file(self, path):
        pass


class Logger:
    """
    
    """
    def __init__(self, debugging_mode, logger_name):
        pass

    def create_logger(self, name: str, parent_logger):
        pass

    def log_info(self, log: str, logger_name):
        pass

    def log_warning(self, log: str, logger_name):
        pass

    def log_error(self, log: str, logger_name):
        pass

    def log_critical(self, log: str, logger_name):
        pass

    def log_debug(self, log: str, logger_name):
        pass

    def log(self, log: str, log_type: str, logger_name):
        pass


class Sender:
    """
    
    """
    def __init__(self, local_ip: str, local_port: int, dest_ip: str, dest_port: int, key: bytes):
        pass

    def wait_for_stop(self):
        pass

    def start_stream(self):
        pass

    def take_screenshot(self):
        """
        This function takes a screenshot of the screen.

Returns:
    bytes: The screenshot of the screen.
        """
        pass

    def split_into_packets(self, data: bytes):
        """
        This function splits the data into packets.

Args:
    data (bytes): The data to split.

Returns:
    list: The list of packets.
        """
        pass

    def send_data(self, packets: list[bytes]):
        """
        This function sends data to the client

Args:
    packets (list[bytes]): The data to send.
        """
        pass


class MultiSender(Sender):
    """
    A class that broadcasts this PC's screen to multiple remote destinations.

Attributes:
    local_ip (str): The local IP address to bind the socket to.
    local_port (int): The local port to bind the socket to.
    dest_port (int): The port of the remote destinations.
    key (bytes): The encryption key to use for encrypting the data.
    """
    def __init__(self, local_port: int, dest_port: int, key: bytes):
        """
        Initializes a ScreenShare object with the specified local and destination ports and encryption key.

Args:
    local_port (int): The local port to bind to.
    dest_port (int): The destination port to send data to.
    key (bytes): The encryption key to use for data transmission.

Returns:
    None
        """
        pass

    def start_stream(self):
        pass

    def stop_stream(self):
        """
        A function that stops the stream.
        
        """
        pass


class Receiver:
    """
    
    """
    def __init__(self, local_ip: str, local_port: int, key: bytes, student_mode: bool):
        pass

    def stop(self):
        """
        This function stops the stream.
        
        """
        pass

    def start_stream(self):
        """
        This function starts the stream.
        
        """
        pass

    def recv_frame(self):
        """
        This function receives packets from the server.

Args:
    s (socket): The socket to receive data from.
        """
        pass

    def show_screenshots(self):
        """
        This function shows the screenshot.
        
        """
        pass

    def recv_frames(self):
        """
        This function continuously receives frames from the server.

Args:
    s (socket): The socket to receive data from.
        """
        pass


class Useful_Functions:
    """
    
    """
    def split_data(encrypted_msg, packet_size):
        """
        This function splits the encrypted message into packets of 4096 bytes.
It also adds a b'END' packet at the end.

Args:
    encrypted_msg (bytes): The encrypted message.

Returns:
    list: A list of packets.
        """
        pass

    def get_MAC_address():
        """
        This function returns the MAC address of the computer

Returns:
    str: The MAC address of the computer
        """
        pass

    def read_file(file_path: str, chunk_size):
        """
        This function reads a file and returns its contents

Args:
    file_path (str): The path to the file

Returns:
    bytes: The contents of the file
        """
        pass


class Cipher:
    """
    This class is used to encrypt and decrypt messages using AES-EAX mode.
It also authenticates the messages using HMAC.
    """
    def __init__(self, key, bytes):
        """
        This function initializes the cipher.

Args:
    key (bytes, optional): The key to use. If None, a random key is generated. Defaults to None.
    bytes (int, optional): The number of bytes to use for the key. Defaults to 32.
        """
        pass

    def encrypt(self, msg):
        """
        This function encrypts the message

Args:
    msg (bytes): The message to encrypt

Returns:
    bytes: The encrypted message
        """
        pass

    def decrypt(self, msg):
        """
        This function decrypts a full message(a message that includes the nonce, tag and ciphertext)

Args:
    msg (bytes): The message to decrypt

Returns:
    bytes: The decrypted message
        """
        pass

    def basic_decrypt(self, msg, nonce, tag):
        """
        This function decrypts a message that only includes the ciphertext.
It also authenticates the message using the nonce and tag.

Args:
    msg (bytes): The message to decrypt

Returns:
    bytes: The decrypted message
        """
        pass

    def set_key(self, key):
        """
        This function sets the key of the cipher.

Args:
    key (bytes): The key to use.
        """
        pass

    def get_key(self):
        """
        This function returns the key of the cipher.

Returns:
    bytes: The key of the cipher
        """
        pass


class Cipher_ECB:
    """
    This class is used to encrypt and decrypt messages using DES mode.
It also authenticates the messages using HMAC.
    """
    def __init__(self, key, bytes):
        """
        This function initializes the cipher.

Args:
    key (bytes, optional): The key to use. If None, a random key is generated. Defaults to None.
    bytes (int, optional): The number of bytes to use for the key. Defaults to 32.
        """
        pass

    def encrypt(self, msg):
        """
        This function encrypts the message

Args:
    msg (bytes): The message to encrypt

Returns:
    bytes: The encrypted message
        """
        pass

    def decrypt(self, msg):
        """
        This function decrypts a full message(a message that includes the nonce, tag and ciphertext)

Args:
    msg (bytes): The message to decrypt

Returns:
    bytes: The decrypted message
        """
        pass

    def set_key(self, key):
        """
        This function sets the key of the cipher.

Args:
    key (bytes): The key to use.
        """
        pass

    def get_key(self):
        """
        This function returns the key of the cipher.

Returns:
    bytes: The key of the cipher
        """
        pass


class Encrypted_TCP_Socket:
    """
    This class is used to create a TCP socket that uses encryption.
    
    """
    def __init__(self, ip, port):
        """
        This function initializes the socket and connects to the server.

Args:
    ip (string): The IP address of the server.
    port (int): The port of the server.
        """
        pass

    def handle_connection(self):
        """
        This function handles the connection to the server.
        
        """
        pass

    def initiate_encrypted_data_transfer(self):
        """
        This function initiates the encrypted data transfer.
        
        """
        pass

    def send_data(self, msg, socket, packet_size, is_file):
        """
        This function encrypts the message and sends it to the server.

Args:
    msg (string): The message to send.
    socket (socket): The socket used to send the data.
        """
        pass

    def decrypt_data(self, data):
        """
        This function decrypts the data using the AES-256 key.

Args:
    data (bytes): The data to decrypt.

Returns:
    bytes: The decrypted data, or False if the decryption failed
        """
        pass

    def recv_data(self, socket):
        """
        This function receives data from the server.
        
        """
        pass

    def send_file(self, path):
        """
        This function sends a file to the server.

Args:
    path (string): The path of the file to send.
        """
        pass

    def recv_file(self, path):
        pass


class Encrypted_TCP_Client(Encrypted_TCP_Socket):
    """
    
    """
    def __init__(self, ip, port, DES_key):
        """
        This function initializes the socket and connects to the server.

Args:
    ip (string): The IP address of the server.
    port (int): The port of the server.
        """
        pass

    def handle_connection(self):
        """
        This function handles the connection to the server.
        
        """
        pass

    def initiate_encrypted_data_transfer(self):
        """
        This function initiates the encrypted data transfer.
        
        """
        pass

    def send_MAC(self):
        """
        This function sends the MAC address of the client to the server.
        
        """
        pass


class Encrypted_TCP_Server(Encrypted_TCP_Socket):
    """
    
    """
    def __init__(self, ip, port, max_connections):
        """
        This function initializes the socket and waits for a connection from a client.

Args:
    ip (string): The IP address of the server.
    port (int): The port of the server.
        """
        pass

    def wait_for_connections(self):
        """
        This function waits for a connection from a client.
        
        """
        pass


class Freezer:
    """
    
    """
    def __init__(self):
        """
        Initializes the Freezer object.
        """
        pass

    def freeze(self):
        """
        Freezes the PC by blocking all keyboard input and starting a thread to freeze the mouse.
        """
        pass

    def freeze_mouse(self):
        """
        Freezes the mouse by continuously moving it to the same position.
        """
        pass

    def unfreeze(self):
        """
        Unfreezes the PC by unblocking all keyboard input.
        """
        pass

    def is_frozen(self):
        """
        Returns whether the PC is currently frozen or not.

Returns:
    bool: True if the PC is frozen, False if not.
        """
        pass


class Main_Window(Tk):
    """
    
    """
    def __init__(self, server):
        pass

    def load_frames(self):
        pass

    def show_frame(self, frame):
        pass

    def check_password(self):
        pass


class Window(Frame):
    """
    
    """
    def __init__(self, master):
        pass

    def load_pcs(self):
        pass

    def create_PCIcon(self, mac, pos, online):
        pass

    def update_icons(self):
        pass


class Main_Frame(Window):
    """
    
    """
    def __init__(self, master):
        pass

    def create_dropdown(self, mac):
        pass

    def create_menubar(self):
        pass

    def assign_dropdown(self, mac):
        pass

    def create_PCIcon(self, mac, pos, online):
        pass

    def show_edit_frame(self):
        pass

    def stream_screen(self):
        pass

    def send_file(self):
        pass


class Edit_Frame(Window):
    """
    
    """
    def __init__(self, master):
        pass

    def create_done_button(self):
        pass

    def create_PCIcon(self, mac, pos, online):
        pass

    def change_location(self, mac, pos):
        pass

    def remove_pc(self, mac):
        pass


class Basic_PCIcon(Canvas):
    """
    
    """
    def __init__(self, master, mac, pos, online):
        pass

    def create_label(self):
        pass

    def change_icon(self):
        pass


class PCIcon_Edit_Mode(Basic_PCIcon):
    """
    
    """
    def __init__(self, master, mac, pos, online):
        pass

    def create_delete_button(self):
        pass

    def make_draggable(self):
        pass

    def on_click(self, event):
        pass

    def on_drag(self, event):
        pass

    def on_release(self, event):
        pass

    def delete_pc(self):
        pass


class PCIcon_View_Mode(Basic_PCIcon):
    """
    
    """
    def __init__(self, master, mac, pos, online):
        pass

    def on_click(self, event):
        pass


class DropDownMenu(Listbox):
    """
    
    """
    def __init__(self, master, mac):
        pass

    def add_options(self):
        pass

    def on_select(self, event):
        pass

    def get_mac(self):
        pass


