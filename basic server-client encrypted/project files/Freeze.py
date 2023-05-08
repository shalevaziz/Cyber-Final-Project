import keyboard
import mouse
import time
from threading import Thread
class Freezer:
    def __init__(self):
        """This function initializes the Freezer
        """
        self.frozen = False
    
    def freeze(self):
        """This function freezes the PC
        """
        for i in range(150):
            keyboard.block_key(i)
        
        self.frozen = True
        t = Thread(target=self.freeze_mouse)
        t.start()

    def freeze_mouse(self):
        """This function freezes the mouse
        """
        while self.frozen:
            mouse.move(1, 1, absolute=True, duration=0) 
    
    def unfreeze(self):
        """This function unfreezes the PC
        """
        keyboard.unhook_all()
        self.frozen = False
    
    def is_frozen(self):
        """This function returns whether the PC is frozen or not

        Returns:
            bool: True if the PC is frozen, False if not
        """
        return self.frozen

if __name__ == "__main__":
    freezer = Freezer()
    freezer.freeze()
    print("Frozen")
    time.sleep(5)
    freezer.unfreeze()
    print("Unfrozen")
    time.sleep(5)
