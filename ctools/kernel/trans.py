from ..conn import cct
from ..utils import *
from ..conn import rtube

import os

class kernel_defaults():
    def __init__(self) -> None:
        self.SRC = os.getenv('CTOOLS_EXP_DIR')
        self.DEST = os.path.join(os.getenv('CTOOLS_WORKSPACE'), 'cpio_tmp', 'pwn')


def unpack_cpio(cpio: str):
    import gzip
    try:
        with gzip.open(cpio, 'rb') as f:
            f.read(1)
        is_gzip = True
    except gzip.BadGzipFile:
        is_gzip = False

    # unpack cpio
    if not is_gzip:
        unpack_intr = f'mkdir -p ./cpio_tmp && cd cpio_tmp && cpio -idmv < ../{cpio}'
    else:
        unpack_intr = f'mkdir -p ./cpio_tmp && cd cpio_tmp && gunzip < ../{cpio} | cpio -idmv'
    
    if os.system(unpack_intr + ' 2>/dev/null') != 0:
        os.system('rm -r ./cpio_tmp')
        errExit(f'Unpack cpio {cpio} error!')


def local_trans(src = None, dest = None, compile = True, cpio: str = 'rootfs.cpio'):
    kdft = kernel_defaults()
    if not src:
        src = kdft.SRC
    if not dest:
        dest = kdft.DEST

    if compile:
        res = os.system(f'cd {src} && make attack')
        if res != 0:
            errExit('Compile error!')

    print(f"\n\n#{' LOCAL TRANSMISSION '.center(70, '=')}#")
    
    if not os.path.exists('./cpio_tmp'):
        unpack_cpio(cpio=cpio)

    if os.system(f'mkdir -p {dest} && cp {src}/attack {dest}') != 0:
        errExit('cp error!')

    pack_intr = f'find . -print0 | cpio --null -ov --format=newc > ../_{cpio} 2>/dev/null'
    if os.system(f'cd ./cpio_tmp && {pack_intr}') != 0:
        errExit('Pack error!')
    success('pack finished.')


def remote_trans(io: rtube.remote, compile = True, src = None):
    kdft = kernel_defaults()
    if not src:
        src = kdft.SRC
    if compile:
        res = os.system(f'cd {src} && make attack')
        if res != 0:
            errExit('Compile error!')

    print(f"\n\n#{' REMOTE TRANSMISSION '.center(70, '=')}#")
    
    from tqdm import tqdm

    with open(f'{src}/attack', 'rb') as f:
        attack = base64.b64encode(f.read())

    io.sendline()
    # io.recvuntil(b'/ $')

    pbar = tqdm(range(0, len(attack), 0x200), 'Sending binary... ')
    for i in pbar:
        if i != 0:
            io.recvuntil(b'/ $')
        io.sendlineafter(b'/ $', b'echo -n \"' + attack[i:i + 0x200] + b'\" >> /tmp/b64_exp')

    io.sendlineafter(b'/ $', b'cat /tmp/b64_exp | base64 -d > /tmp/attack')
    io.sendlineafter(b'/ $', b'chmod +x /tmp/attack')
    success('Transmission finished.')