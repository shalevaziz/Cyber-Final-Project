import tkinter as tk
from tkinter import font, messagebox, filedialog
from PIL import Image, ImageTk
import json
from threading import Thread
import time
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
        self.current_frame.destroy()
        self.current_frame_name = frame
        self.current_frame = self.frames[self.current_frame_name](self)
        self.current_frame.pack(anchor='nw', fill='both', expand=True)
        self.current_frame.load_pcs()

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
                time.sleep(2)
            
            
class Main_Frame(Window):
    def __init__(self, master):
        super().__init__(master)
        self.create_widgets()

        self.master.server.allow_new_connections = False

        self.bind('<Button-1>', lambda event: self.dropdown.place_forget())
        

    def create_widgets(self):
        self.create_menubar()
        
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
        print(file_path)
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

