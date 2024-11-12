from pwn import *

class link_map():
    DT_PLTGOT = 3
    DT_STRTAB = 5
    DT_SYMTAB = 6
    DT_FINI = 13
    DT_DEBUG = 21
    DT_JMPREL = 23
    DT_FINI_ARRAY = 26
    DT_FINI_ARRAYSZ = 28
    DT_VERNUM = 50


    def __init__(self, address: int = 0) -> None:
        self.address: int = address
    
    def l_addr(self):
        return self.address
    
    def l_info(self, tag):
        return self.address + 0x40 + 8 * tag
    
    def l_init_called(self):
        return self.address + 0x31c
    