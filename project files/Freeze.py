import keyboard
import mouse
import time
from threading import Thread


class Freezer:
    def __init__(self):
        """Initializes the Freezer object."""
        self.frozen = False
    
    def freeze(self):
        """Freezes the PC by blocking all keyboard input and starting a thread to freeze the mouse."""
        for i in range(150):
            keyboard.block_key(i)
        
        self.frozen = True
        t = Thread(target=self.freeze_mouse)
        t.start()

    def freeze_mouse(self):
        """Freezes the mouse by continuously moving it to the same position."""
        while self.frozen:
            mouse.move(1, 1, absolute=True, duration=0) 
    
    def unfreeze(self):
        """Unfreezes the PC by unblocking all keyboard input."""
        keyboard.unhook_all()
        self.frozen = False
    
    def is_frozen(self):
        """Returns whether the PC is currently frozen or not.

        Returns:
            bool: True if the PC is frozen, False if not.
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