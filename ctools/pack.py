from pwn import pack, unpack
from typing import Literal

def p64(number: int, 
        endianness: Literal['little', 'big'] = 'little', 
        sign: bool = False):
    return pack(number, 64, endianness=endianness, sign=sign)

def p32(number: int, 
        endianness: Literal['little', 'big'] = 'little', 
        sign: bool = False):
    return pack(number, 32, endianness=endianness, sign=sign)

def p16(number: int, 
        endianness: Literal['little', 'big'] = 'little', 
        sign: bool = False):
    return pack(number, 16, endianness=endianness, sign=sign)

def p8(number: int, 
        endianness: Literal['little', 'big'] = 'little', 
        sign: bool = False):
    return pack(number, 8, endianness=endianness, sign=sign)

def u64(data: int):
    return unpack(data, 64)

def u32(data: int):
    return unpack(data, 32)

def u16(data: int):
    return unpack(data, 16)

def u8(data: int):
    return unpack(data, 8)

def p64x(number: int, endianness: Literal['little', 'big']='little'):
    number %= 1 << 64
    return p64(number, endianness=endianness)

def p32x(number: int, endianness: Literal['little', 'big']='little'):
    number %= 1 << 32
    return p32(number, endianness=endianness)

def p16x(number: int, endianness: Literal['little', 'big']='little'):
    number %= 1 << 16
    return p16(number, endianness=endianness)

def p8x(number: int, endianness: Literal['little', 'big']='little'):
    number %= 1 << 8
    return p8(number, endianness=endianness)