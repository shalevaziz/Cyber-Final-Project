import tkinter as tk
from PIL import Image, ImageTk
import json

class SetupWindow(tk.Frame):
    def __init__(self, master=None):
        global PC_ICON_ONLINE, PC_ICON_OFFLINE, X_ICON
        self.master = master
        self.master.geometry("1200x1200")
        self.master.title("First Setup")
        self.pcs = {}
        super().__init__(master, width = 1200, height = 1200)
        
        self.place(x = 0, y = 0)
        PC_ICON_ONLINE = ImageTk.PhotoImage(Image.open(r"basic server-client encrypted/icons/pc_icon_online.png").resize((100, 100)))
        PC_ICON_OFFLINE = ImageTk.PhotoImage(Image.open(r"basic server-client encrypted/icons/pc_icon_offline.png").resize((100, 100)))
        X_ICON = ImageTk.PhotoImage(Image.open(r"basic server-client encrypted/icons/x_icon.png").resize((20, 20)))
        self.load_pcs()

    def load_pcs(self):
        with open('locations.json', 'r') as f:
            self.pcs = json.load(f)
            
        for pc in self.pcs.items():
            self.create_PCIcon(pc[0], pc[1])
            
    def create_PCIcon(self, mac, pos = (0,0)):
        PCIcon(self, mac, pos, draggable = True)
        self.pcs = {mac:(0,0)}
    
    def change_location(self, mac, pos):
        self.pcs[mac] = tuple(pos)
        with open('locations.json', 'w') as f:
            json.dump(self.pcs, f)

    def remove_pc(self, mac):
        self.pcs.pop(mac)
        with open('locations.json', 'w') as f:
            json.dump(self.pcs, f)

class PCIcon(tk.Canvas):
    def __init__(self, master, mac, pos, draggable = False, online = True):
        super().__init__(master, width=130, height=130)
        
        self.mac = mac
        self.draggable = draggable
        self.online = online
        self.pos = pos
        self.place(x = self.pos[0], y = self.pos[1])
        
        self.label = tk.Label(self, text = self.mac)
        self.label.place(x = 0, y = 110)
        
        """self.delete_button = tk.Button(self, image = X_ICON, command = self.destroy, borderwidth=0, highlightthickness = 0, bd = 0, pady=0, padx=0)
        self.delete_button.place(x = 110, y = 0)"""
        
        self.delete_button = tk.Label(self, image = X_ICON)
        self.delete_button.place(x = 110, y = 0)
        #self.delete_button.configure(bg = '')
        self.delete_button.bind("<Button-1>", lambda event: self.delete_pc())
        
        self.change_icon()
        if self.draggable:
            self.make_draggable()
    
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
    
    def change_icon(self):
        if self.online:
            self.create_image(10,5, anchor = tk.NW, image = PC_ICON_ONLINE)
        else:
            self.create_image(10,5, anchor = tk.NW, image = PC_ICON_OFFLINE)
    
    def delete_pc(self):
        self.master.remove_pc(self.mac)
        super().destroy()
    
main = tk.Tk()
app = SetupWindow(master=main)
app.mainloop()
