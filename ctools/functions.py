from pwn import *
from typing import Mapping, Literal, Union

from .utils import *
from .pack import *

def guess_bit():
    return int(input("The accurate hex bits> "), 16)


def stdout_leak(res: bytes, skip: int = 0) -> int:
    """ Sometimes the address of libc is not start with \x7f, and we may leak qword by qword.

    Args:
        res (bytes): raw data.
        skip (int, optional): skip n results. Defaults to 0.

    Returns:
        int: the address that leaked
    """
    while True:
        info('Processing %s' % ' '.join([format(byte, '02X') for byte in res[:8]]))
        leak = u64(res[:8])
        if leak > 0x700000000000 and leak < 0x800000000000:
            info('skip ==> %d' % skip)
            if skip <= 0:
                return leak
            skip -= 1
        res = res[8:]


def sockaddr_in(host: str, port: int, family: int = 2):
    """Return a C structure describing an Internet socket address. 

    Args:
        host (str): host address
        port (int): port
        family (int, optional): family field. Defaults to 2.

    Returns:
        server_addr: sockaddr_in structure
    """
    assert 0 < port < 0x10000 and 0 < family < 0x10000, 'port or family not uint16'

    server_addr = b''
    server_addr += p16(family)
    server_addr += p8((port >> 8) & 0xff)
    server_addr += p8(port & 0xff)
    host_list = host.split('.')
    assert len(host_list) == 4, 'IP not correct'
    for num in host_list:
        server_addr += p8(int(num))
    assert len(server_addr) == 8
    server_addr += p64(0)
    return server_addr


def to_varint(value: int, encode: Literal['Varint', 'Zigzag'] = 'Varint') -> bytes:
    """Convert an integer to a varint.

    Args:
        value (int): The integer to convert.
        encode (str, optional): Varint encode mode. 'Varint' or 'Zigzag'. Defaults to 'Varint'

    Returns:
        bytes: The varint
    """
    if value == 0:
        return b'\x00'
    if encode == 'Zigzag':
        if value > 0:
            value *= 2
        else:
            value = abs(value) * 2 - 1
    res = []
    while value:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        res.append(byte)
    return bytes(res)


### from https://github.com/MuelNova/PwnUtils/blob/main/pwnutils/protocol/protobuf.py
def protobuf_serialize(obj: Union[Mapping, list], unsign: list = []) -> bytes:
    """Serialize a protobuf object.

    Args:
        obj (Union[Mapping, list]): The object to serialize.
        unsign (list): Unsigned field number

    Returns:
        bytes: Serialized bytes.

    Examples:
        obj = {
            'id': 123,
            'name': 'Alice',
            'is_passed': True
        }

        obj = [123, 'Alice', None, True]

        obj = {
                1: 123,
                2: 'Alice',
                4: True
            }
        
        # first field is unsigned, the second and third is signed
        protobuf_serialize(obj=[1, 2, 3], unsign=[1])
    """

    if isinstance(obj, Mapping):
        keys = obj.keys()
        if all(isinstance(key, int) for key in keys):
            runner = sorted(obj.items())
        else:
            runner = enumerate(obj.values(), start=1)
    elif isinstance(obj, list):
        runner = enumerate(obj, start=1)
    else:
        raise ValueError(f"Unsupported type: {type(obj)}")
    
    message = b''
    for key, value in runner:
        field_number = key << 3
        if isinstance(value, int):
            message += to_varint(field_number | 0)
            if key in unsign:
                message += to_varint(value)
            else:
                message += to_varint(value, encode='Zigzag')
        elif isinstance(value, (str, bytes)):
            if isinstance(value, str):
                value = value.encode()
            message += to_varint(field_number | 2) + to_varint(len(value)) + value
        elif isinstance(value, bool):
            message += to_varint(field_number | 0) + b'\x01' if value else b'\x00'
        elif value is None:
            continue
        else:
            raise ValueError(f"Unsupported type {type(value)} of value {value}")
    return message


def print_payload(pad: bytes, nbytes_per_line: int = 32, nbytes_per_group: int = 8, 
                  full_hex: bool = False, character: bool = False,
                  errpos: int = -1, startpos: int = -1, endpos: int = -1):
    """ print payload more clearly

    Args:
        pad (bytes): payload
        nbytes_per_line (int, optional): print nbytes per line. Defaults to 32.
        nbytes_per_group (int, optional): print nbytes per group. Defaults to 8.
        full_hex (bool, optional): print as hex full number. Defaults to False.
        character (bool, optional): print character. Defaults to False.
        errpos (int, optional): error character position if not -1. Defaults to -1.
        startpos (int, optional): start pos. Defaults to -1.
        endpos (int, optional): end pos. Defaults to -1.

    Examples:
    >>> print_payload(b'a' * 0x10)
           0x0: 61 61 61 61 61 61 61 61   61 61 61 61 61 61 61 61
    
    >>> print_payload(b'a' * 0x10, 8)
           0x0: 61 61 61 61 61 61 61 61
           0x8: 61 61 61 61 61 61 61 61

    >>> print_payload(b'a' * 0x10, full_hex=True)
           0x0: 0x6161616161616161  0x6161616161616161

    >>> pprint_payload(b'\x01\x0aabc01\xde', character=True)
           0x0: 01 0A 61 62 63 30 31 DE
                .  \n a  b  c  0  1  .
                
    >>> print_payload(b'a' * 0x30 + p64(0xdeadbeef), startpos=0x30)
          0x30: EF BE AD DE 00 00 00 00
        
    >>> pad = b'a' * 0x10 + b'\x00' + b'b' * 0x10
        for i in range(len(pad)):
            if pad[i] == 0:
                print_payload(pad, errpos=i)

        #=============================================== ERROR PAYLOAD ================================================#
           0x0: 61 61 61 61 61 61 61 61   61 61 61 61 61 61 61 61   00 62 62 62 62 62 62 62   62 62 62 62 62 62 62 62   
                                                                    ^^ ERROR CHARACTER
    """
    if errpos != -1:
        print(f"\n#{' ERROR PAYLOAD '.center(110, '=')}#")
        startpos = (errpos // nbytes_per_line) * nbytes_per_line
        endpos = startpos + nbytes_per_line

    if startpos == -1:
        startpos = 0
    if endpos == -1:
        endpos = len(pad)

    pchar = character and not full_hex
    to_char = None
    
    pad = pad[startpos:endpos]
    nb = len(pad)
    pp = startpos

    if pchar:
        to_char = lambda x: chr(x).ljust(2, ' ') if 0x21 <= x <= 0x7e else (
            '\\n' if x == 0xa else '\\r' if x == 0xd else '\\s' if x == 0x20 else '. '
        )

    for line in range(upper_align(nb, nbytes_per_line) // nbytes_per_line):
        block = pad[line * nbytes_per_line : (line + 1) * nbytes_per_line]
        ngroup = upper_align(len(block), nbytes_per_group) // nbytes_per_group
        _block = ''
        _block_char = ''
        for igroup in range(ngroup):
            raw = block[igroup * nbytes_per_group : (igroup + 1) * nbytes_per_group]
            if full_hex:
                _block += f'{unpack(raw, len(raw * 8)):#x}'
            else:
                _block += ''.join([f'{x:02X} ' for x in raw])
            
            if pchar:
                _block_char += ''.join([to_char(x) + ' ' for x in raw]) + '  '

            _block += '  '
        print(f'{pp:#6x}: ' + _block)
        if pchar:
            print(' ' * 0x8 + _block_char)
        pp += nbytes_per_line
    
    if errpos != -1:
        inline_pos = errpos % nbytes_per_line
        print(' ' * (0x8 + 3 * inline_pos + 2 * (inline_pos // nbytes_per_group)) + 
              COLOR_RED + '^^ ERROR CHARACTER' + COLOR_RESET)


def check_payload(pad: bytes, black_list: list = None, white_list: list = None):
    """ check if payload includes invalid character (black_list) or includes only valid character (white_list)

    Args:
        pad (bytes): payload
        black_list (list, optional): black list mode . Defaults to None.
        white_list (list, optional): white list mode. Defaults to None.

    Raises:
        ctoolsError: invalid mode
    """
    if black_list is not None:
        mode = 'BLACK'
    elif white_list is not None:
        mode = 'WHITE'
    else:
        raise ctoolsError('black list and white list are all none')
    
    suc = True
    if mode == 'BLACK':
        for pos in range(len(pad)):
            if pad[pos] in black_list:
                print_payload(pad, errpos=pos)
                suc = False
                break
    elif mode == 'WHITE':
        for pos in range(len(pad)):
            if pad[pos] not in white_list:
                print_payload(pad, errpos=pos)
                suc = False
                break
    if not suc:
        fail('Bad payload')
        exit(1)
    success('Payload check pass')


def check_space(pad: bytes):
    """check can the given payload can be read by `cin`.
    black_list: [` `, `\\n`, `\\r`, `\\f`, `\\v`, `\\t`]

    Args:
        pad (bytes): payload
    """
    blist = [0x9, 0x0a, 0xb, 0xc, 0xd, 0x20]
    check_payload(pad, black_list=blist)


def crack_key(io, length: int, prefix: bytes, bad: bytes, good: bytes, prepend: bytes = b'',
               charset: Union[list, bytes] = range(0, 0x100), verbose: bool = True,
               finish: Union[str, None] = None, fn = None, args: list = [], kwargs: dict = {}) -> bytes:
    key = prepend
    for l in range(len(prepend), length):
        for x in charset:
            key += p8(x)
            if fn is not None:
                fn(*args, **kwargs)
            io.sendlineafter(prefix, key)
            res = io.recvuntil(b'\n')
            if finish is not None and finish in res:
                success(f'{key = }')
                return key
            elif good is not None and good in res:
                if verbose:
                    print(l, key)
                break
            elif bad is not None and bad in res:
                key = key[:-1]
            else:
                key = key[:-1]
    success(f'{key = }')
    return key
