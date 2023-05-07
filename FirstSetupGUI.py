import tkinter as tk
from tkinter import font, messagebox
from PIL import Image, ImageTk
import json

class Main_Window(tk.Tk):
    def __init__(self):
        super().__init__()
        self.geometry("1200x800")
        self.title("First Setup")
        self.resizable(False, False)
        self.frames = {}
        self.load_frames()
        self.current_frame = 'main'
        self.show_frame(self.current_frame)
        self.mainloop()
    
    def load_frames(self):
        self.frames['main'] = Main_Frame(self)
        self.frames['edit'] = Edit_Frame(self)
    
    def show_frame(self, frame):
        self.frames[self.current_frame].pack_forget()
        self.frames[frame].pack(anchor='nw', fill='both', expand=True)
        self.frames[frame].load_pcs()
        self.current_frame = frame


class Window(tk.Frame):
    def __init__(self, master=None):
        global PC_ICON_ONLINE, PC_ICON_OFFLINE, X_ICON
        self.master = master
        self.master.geometry("1200x800")
        self.master.title("First Setup")
        self.master.resizable(False, False)
        self.pcs_pos = {}
        self.pcs = []
        super().__init__(master, width = 1200, height = 800)
        
        PC_ICON_ONLINE = ImageTk.PhotoImage(Image.open(r"basic server-client encrypted/icons/pc_icon_online.png").resize((100, 100)))
        PC_ICON_OFFLINE = ImageTk.PhotoImage(Image.open(r"basic server-client encrypted/icons/pc_icon_offline.png").resize((100, 100)))
        X_ICON = ImageTk.PhotoImage(Image.open(r"basic server-client encrypted/icons/x_icon.png").resize((20, 20)))
        self.load_pcs()
    
    def load_pcs(self):
        for pc in self.pcs:
            if pc is not None:
                pc.destroy()

        self.pcs = []

        with open('locations.json', 'r') as f:
            self.pcs_pos = json.load(f)
        
        for pc in self.pcs_pos.items():
            self.pcs.append(self.create_PCIcon(pc[0], pc[1]))
    
    def create_PCIcon(self, mac, pos = (0,0)):
        raise NotImplementedError('This function is not implemented in the base class')

class Main_Frame(Window):
    def __init__(self, master=None):
        super().__init__(master)
        self.create_widgets()
        self.bind('<Button-1>', lambda event: self.dropdown.place_forget())

    def create_widgets(self):
        self.create_dropdown()
        self.create_edit_button()

    def create_dropdown(self):
        self.dropdown = DropDownMenu(self)

    def create_edit_button(self):
        self.edit_button = tk.Button(self, text = 'Edit', command = lambda: self.master.show_frame('edit'))
        self.edit_button.place(x = 1100, y = 700)

    def assign_dropdown(self, mac):
        pos = self.pcs_pos[mac]
        self.dropdown.place(x = pos[0]+10, y = pos[1]+130)
        self.dropdown.set_mac(mac)
    
    def create_PCIcon(self, mac, pos = (0,0)):
        PCIcon_View_Mode(self, mac, pos)
        self.pcs_pos[mac] = pos

class Edit_Frame(Window):
    def __init__(self, master=None):
        super().__init__(master)
        self.create_done_button()
    
    def create_done_button(self):
        self.done_button = tk.Button(self, text = 'Save', command = lambda: self.master.show_frame('main'))
        self.done_button.place(x = 1100, y = 700)

    def create_PCIcon(self, mac, pos = (0,0)):
        PCIcon_Edit_Mode(self, mac, pos)
        self.pcs_pos = {mac:pos}
    
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
    def __init__(self, master):
        text_font = font.Font(family = "Calibri", size = 13)
        super().__init__(master, width = 11, height = 3, selectmode = tk.SINGLE, font=text_font)
        self.mac = None
        self.insert(0,"See Screen")
        self.insert(1,"Delete")
        self.bind("<<ListboxSelect>>", self.on_select)
    
    def on_select(self, event):
        selection = self.curselection()
        print(self.get(selection[0]))
    
    def set_mac(self, mac):
        self.mac = mac
    
    def get_mac(self):
        return self.mac

main = Main_Window()
