from pwn import *
import os

COLOR_REDX = '\033[1;31m'
COLOR_RED = '\033[31m'
COLOR_GREENX = '\033[1;32m'
COLOR_RESET = '\033[0m'

glibc_all_in_one = os.getenv('GLIBC_ALL_IN_ONE')
libs = os.getenv('CTOOLS_LIBS')
workspace = os.getenv('CTOOLS_WORKSPACE')

def ASSERT_LIBC_BASE(libc_base):
    assert libc_base >= 0x700000000000 and libc_base < 0x800000000000 and (libc_base & 0xfff) == 0


class ctoolsError(RuntimeError):
    def __init__(self, message: str):
        self.args = [message]


class libcNotExistError(RuntimeError):
    def __init__(self, message: str = ''):
        if message != '': self.args = [message]
        else: self.args = ['Libc not exist']


def path2ELF(path: str, checksec = False) -> elf.ELF:
    """ convert path to elf.ELF, or return the parameter itself if it's already a ELF type.

    Args:
        path (str): path of libc to convert to ELF
        checksec (bool, optional): whether to checksec. Defaults to False.

    Raises:
        libcNotExistError: file not exist or not a ELF file
        ctoolsError: if type is not match

    Returns:
        elf.ELF: the ELF
    """
    if isinstance(path, str):
        try:
            return ELF(path, checksec=checksec)
        except:
            raise libcNotExistError('File not exist or not an ELF file')
    elif isinstance(path, elf.ELF):
        return path
    else:
        raise ctoolsError('Type not match')
    

def walk_libs():
    from .conn import cct
    if cct.libs is not None:
        return cct.libs
    std_libs = []
    arch = context.arch
    for _, _, files in os.walk(libs):
        for file in files:
            std_libs += re.findall('^.*_%s\.so$' % arch, file)
    std_libs = sorted(std_libs)
    cct.libs = std_libs
    return std_libs


def fail(msg: str):
    print(f'[{COLOR_REDX}-{COLOR_RESET}] ' + msg)


def errExit(msg: str):
    fail(msg)
    exit(1)


def chwsp(path: str):
    global workspace
    workspace = os.path.join(workspace, path)
    os.chdir(workspace)
    os.environ['CTOOLS_WORKSPACE'] = workspace

def upper_align(x_len: int, align: int) -> int:
    return x_len + ((align - x_len) % align)