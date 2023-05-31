import tkinter as tk
from tkinter import font, messagebox, filedialog
from PIL import Image, ImageTk
import json
from threading import Thread
import time
import os
from hashlib import sha256
from basics import Cipher
class Main_Window(tk.Tk):
    """The root object of the program.
    """
    def __init__(self, server):
        """Initializes the Main_Window object.

        Args:
            server (basics.Server): The server object to use for the connection.
        """
        super().__init__()
        self.geometry("1200x800")
        self.title("ClassViewer")
        self.resizable(False, False)
        
        self.frames = {}
        self.load_frames()
        
        self.server = server

        self.current_frame_name = 'main'
        self.current_frame = self.frames[self.current_frame_name](self)
        self.current_frame.pack(anchor='nw', fill='both', expand=True)
        

        
        self.mainloop()
    
    def load_frames(self):
        """Loads all the frames into the frames dictionary."""
        self.frames['main'] = Main_Frame
        self.frames['edit'] = Edit_Frame
    
    def show_frame(self, frame):
        """Shows the specified frame.
        
        Args:
            frame (str): The name of the frame to show.
        """
        if frame == 'edit':
            if not self.check_password():
                return
        self.current_frame.destroy()
        self.current_frame_name = frame
        self.current_frame = self.frames[self.current_frame_name](self)
        self.current_frame.pack(anchor='nw', fill='both', expand=True)
        self.current_frame.load_pcs()
    
    def check_password(self):
        """Checks if the password is correct.

        Returns:
            bool: True if the password is correct, False otherwise.
        """
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
    """The base class for all the frames. Abstract.
    """
    def __init__(self, master=None):
        """Initializes the Window object.

        Args:
            master (tk.Tk): The root object of the program. Defaults to None.
        """
        global PC_ICON_ONLINE, PC_ICON_OFFLINE, X_ICON
        self.master = master
        self.master.geometry("1200x800")
        self.master.resizable(False, False)
        self.pcs_pos = {}
        self.pcs = {}
        super().__init__(master, width = 1200, height = 800)
        
        PC_ICON_ONLINE = ImageTk.PhotoImage(Image.open(r"icons/pc_icon_online.png").resize((100, 100)))
        PC_ICON_OFFLINE = ImageTk.PhotoImage(Image.open(r"icons/pc_icon_offline.png").resize((100, 100)))
        X_ICON = ImageTk.PhotoImage(Image.open(r"icons/x_icon.png").resize((20, 20)))
        
        Thread(target=self.update_icons).start()
    
    def load_pcs(self):
        """Loads the pcs from the locations.json file and creates the PCIcons."""
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
        """Creates a PCIcon object. Abstract.

        Args:
            mac (str): The mac address of the PC.
            pos (tuple, optional): The position of the PCIcon. Defaults to (0,0).
            online (bool, optional): Whether the PC is online or not. Defaults to True.
        """
        raise NotImplementedError('This function is not implemented in the base class')

    def update_icons(self):
        """Updates the icons of the PCs for their online status.
        """
        while self.winfo_exists():
            self.load_pcs()
            self.master.server.new_connection = False
            while not self.master.server.new_connection and self.winfo_exists():
                time.sleep(3)

class Main_Frame(Window):
    """The main frame of the program.
    """
    def __init__(self, master):
        """Initializes the Main_Frame object.

        Args:
            master (tk.Tk): The root object of the program.
        """
        super().__init__(master)
        self.create_menubar()

        self.master.server.allow_new_connections = False

        self.bind('<Button-1>', lambda event: self.dropdown.place_forget())

    def create_dropdown(self, mac):
        """Creates a dropdown menu for the specified PC.

        Args:
            mac (str): The mac address of the PC.
        """
        self.dropdown = DropDown_Menu(self, mac)

    def create_menubar(self):
        """Creates the menubar."""
        self.menubar = tk.Menu(self)
        actions_menu = tk.Menu(self.menubar, tearoff = 0)
        actions_menu.add_command(label = 'Edit', command = self.show_edit_frame)
        actions_menu.add_command(label = 'Stream Screen', command = lambda: self.master.server.stream_screen())
        actions_menu.add_command(label = 'Send File', command = self.send_file)
        actions_menu.add_command(label = 'Open URL', command = self.open_url)
        self.menubar.add_cascade(label = 'Actions', menu = actions_menu)
        
        self.master.config(menu = self.menubar)
        
    def assign_dropdown(self, mac):
        """Assigns the dropdown menu to the specified PC.

        Args:
            mac (str): The mac address of the PC.
        """
        if not self.pcs[mac].online:
            return
        self.create_dropdown(mac)
        pos = self.pcs_pos[mac]
        self.dropdown.place(x = pos[0]+10, y = pos[1]+130)

        self.dropdown.tkraise()
    
    def create_PCIcon(self, mac, pos = (0,0), online = True):
        """Creates a PCIcon object. Implements the abstract method from the base class.

        Args:
            mac (str): The mac address of the PC.
            pos (tuple, optional): The position of the PCIcon. Defaults to (0,0).
            online (bool, optional): Whether the PC is online or not. Defaults to True.
        
        Returns:
            PCIcon_View_Mode: The PCIcon object.
        """
        pc_icon = PCIcon_View_Mode(self, mac, pos, online)
        self.pcs_pos[mac] = pos
        return pc_icon

    def show_edit_frame(self):
        """Shows the edit frame.
        """
        if self.master.server.streaming_screen:
            messagebox.showerror('Error', 'You cannot edit the locations while streaming the screen')
            return
        
        self.master.show_frame('edit')
    
    def stream_screen(self):
        """Streams the screen of the PC.
        """
        if self.master.server.streaming_screen:
            messagebox.showerror('Error', 'You are already streaming the screen')
            return
        
        self.master.server.stream_screen()
    
    def send_file(self):
        """Sends a file to all connected PCs.
        """
        file_path = filedialog.askopenfilename()
        if file_path == '':
            return
        self.master.server.send_file_to_all(file_path)

    def open_url(self):
        """Opens a URL on all connected PCs.
        """
        url = tk.simpledialog.askstring('Open URL', 'Enter the URL to open')
        if url is None:
            return
        self.master.server.open_url_on_all(url)
class Edit_Frame(Window):
    """The edit frame of the program.
    """
    def __init__(self, master):
        """Initializes the Edit_Frame object.

        Args:
            master (tk.Tk): The root object of the program.
        """
        super().__init__(master)
        self.create_done_button()
        self.load_pcs()
        
        self.master.server.allow_new_connections = True
    
    def create_done_button(self):
        """Creates the done button.
        """
        self.done_button = tk.Button(self, text = 'Save', command = lambda: self.master.show_frame('main'))
        self.done_button.place(x = 1100, y = 700)

    def create_PCIcon(self, mac, pos = (0,0), online = True):
        """Creates a PCIcon object. Implements the abstract method from the base class.

        Args:
            mac (str): The mac address of the PC.
            pos (tuple, optional): The position of the PCIcon. Defaults to (0,0).
            online (bool, optional): Whether the PC is online or not. Defaults to True.

        Returns:
            PCIcon_Edit_Mode: The PCIcon object.
        """
        pc_icon = PCIcon_Edit_Mode(self, mac, pos, online)
        self.pcs_pos[mac] = pos
        return pc_icon
    
    def change_location(self, mac, pos):
        """Changes the location of the PC.

        Args:
            mac (str): The mac address of the PC.
            pos (tuple): The new position of the PC.
        """
        self.pcs_pos[mac] = tuple(pos)
        with open('locations.json', 'w') as f:
            json.dump(self.pcs_pos, f)

    def remove_pc(self, mac):
        """Removes the PC from the list.

        Args:
            mac (str): The mac address of the PC.
        """
        self.pcs_pos.pop(mac)
        with open('locations.json', 'w') as f:
            json.dump(self.pcs_pos, f)

class Basic_PCIcon(tk.Canvas):
    """The base class for the PCIcon objects.
    """
    def __init__(self, master, mac, pos, online = True):
        """Initializes the Basic_PCIcon object.
        
        Args:
            master (tk.Tk): The root object of the program.
            mac (str): The mac address of the PC.
            pos (tuple): The position of the PCIcon.
            online (bool, optional): Whether the PC is online or not. Defaults to True.
        """
        super().__init__(master, width=130, height=130)
        
        self.mac = mac
        self.online = online
        self.pos = pos

        self.place(x = self.pos[0], y = self.pos[1])
        
        self.create_label()
        self.change_icon()

    def create_label(self):
        """Creates the label of the PCIcon.
        """
        self.label = tk.Label(self, text = self.mac)
        self.label.place(x = 0, y = 110)

    def change_icon(self):
        """Changes the icon of the PCIcon.
        """
        if self.online:
            self.create_image(10,5, anchor = tk.NW, image = PC_ICON_ONLINE)
        else:
            self.create_image(10,5, anchor = tk.NW, image = PC_ICON_OFFLINE)

class PCIcon_Edit_Mode(Basic_PCIcon):
    """The PCIcon object for the edit frame.
    """
    def __init__(self, master, mac, pos, online = True):
        """Initializes the PCIcon_Edit_Mode object.

        Args:
            master (tk.Tk): The root object of the program.
            mac (str): The mac address of the PC.
            pos (tuple): The position of the PCIcon.
            online (bool, optional): Whether the PC is online or not. Defaults to True.
        """
        super().__init__(master, mac, pos, online = online)
        
        self.create_delete_button()
        
        self.make_draggable()
    
    def create_delete_button(self):
        """Creates the delete button.
        """
        self.delete_button = tk.Label(self, image = X_ICON)
        self.delete_button.place(x = 110, y = 0)
        self.delete_button.bind("<Button-1>", lambda event: self.delete_pc())

    def make_draggable(self):
        """Makes the PCIcon draggable.
        """
        self.bind("<Button-1>", self.on_click)
        self.bind("<B1-Motion>", self.on_drag)
        self.bind("<ButtonRelease-1>", self.on_release)
    
    def on_click(self, event):
        """The function that is called when the PCIcon is clicked.

        Args:
            event (tk.Event): The event object.
        """
        self.start_x = event.x
        self.start_y = event.y
    
    def on_drag(self, event):
        """The function that is called when the PCIcon is dragged.

        Args:
            event (tk.Event): The event object.
        """
        x = self.winfo_x() - self.start_x + event.x
        y = self.winfo_y() - self.start_y + event.y
        self.place(x = x, y = y)
        self.pos = (x, y)
    
    def on_release(self, event):
        """The function that is called when the PCIcon is released.

        Args:
            event (tk.Event): The event object.
        """
        self.master.change_location(self.mac, self.pos)
    
    def delete_pc(self):
        """Deletes the PCIcon.
        """
        response = messagebox.askquestion("Delete PC", "Are you sure you want to delete this PC?", icon = 'warning')
        if response == 'yes':
            self.master.remove_pc(self.mac)
            super().destroy()

class PCIcon_View_Mode(Basic_PCIcon):
    """The PCIcon object for the view frame.
    """
    def __init__(self, master, mac, pos, online = True):
        """Initializes the PCIcon_View_Mode object.
        
        Args:
            master (tk.Tk): The root object of the program.
            mac (str): The mac address of the PC.
            pos (tuple): The position of the PCIcon.
            online (bool, optional): Whether the PC is online or not. Defaults to True.
        """
        super().__init__(master, mac, pos, online = online)
        self.bind("<Button-1>", self.on_click)

    def on_click(self, event):
        """The function that is called when the PCIcon is clicked.
        """
        x = self.winfo_x()
        y = self.winfo_y()
        self.master.assign_dropdown(self.mac)

class DropDown_Menu(tk.Listbox):
    """The dropdown menu for the PCIcon_View_Mode object.
    """
    def __init__(self, master, mac):
        """Initializes the DropDown_Menu object.

        Args:
            master (tk.Tk): The root object of the program.
            mac (str): The mac address of the PC.
        """
        text_font = font.Font(family = "Calibri", size = 13)
        super().__init__(master, width = 11, height = 3, selectmode = tk.SINGLE, font=text_font)
        self.mac = mac

        self.is_frozen = self.master.master.server.conns[self.mac].is_frozen
        
        self.add_options()
    
        self.bind("<<ListboxSelect>>", self.on_select)

    def add_options(self):
        """Adds the options to the dropdown menu.
        """
        self.insert(0,"See Screen")
        if self.is_frozen:
            self.insert(1,"Unfreeze")
        else:
            self.insert(1,"Freeze")
            
        self.insert(2,"Send File")
        self.insert(3,"Open URL")
    
    def on_select(self, event):
        """The function that is called when an option is selected.

        Args:
            event (tk.Event): The event object.
        """
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

        elif selection == 2:#Send File
            file_path = filedialog.askopenfilename()
            self.master.master.server.conns[self.mac].send_file(file_path)
        
        elif selection == 3:#Open URL
            URL = tk.simpledialog.askstring("Open URL", "Enter the URL you want to open:")
            self.master.master.server.conns[self.mac].open_URL(URL)
    
    def get_mac(self):
        """Returns the mac address of the PC.
        
        Returns:
            str: The mac address of the PC.
        """
        return self.mac

