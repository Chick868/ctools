from pwn import *
from typing import Union

from .utils import *
from .LibcSearcher import *
from .conn import cct

# check if two libc equal by check their offset 
CHECK_LIST = ('system', 'malloc', 'execve', 'clone', '_IO_2_1_stdout_')


def elf_X(elf: str):
    os.system(f'chmod u+x {elf}')


def choose_glibc_from_std() -> str:
    libs = walk_libs()
    print('--------------------------------------')
    for i in range(libs.__len__()):
        print(f'[{i + 1}] {libs[i]}')
    print('--------------------------------------')
    choice = int(input('Please input the glibc you want to patch: '))
    return libs[choice - 1]


def find_std_glibc(libc_path: Union[elf.ELF, str]) -> Union[str, None]:
    """ Find std-libc version that matches the `libc_path`

    Args:
        libc (elf.ELForstr): the path or ELF of libc

    Raises:
        libcNotExistError: if libc not exist

    Returns:
        str or None: the std-libc version that matches or None if nothing matches
    """
    libc = path2ELF(libc_path)
    funcs = {}

    for func in CHECK_LIST:
        funcs[func] = libc.symbols[func]
    return LibcSearcher(funcs, libc_path=libc_path)


def patch_elf(elf: str, rpath: str, ld_path: str = '') -> bool:
    if ld_path != '':
        if os.system(f'patchelf --set-interpreter "{ld_path}" "{elf}"') != 0:
            return False
    if rpath != '':
        if os.system(f'patchelf --set-rpath "{rpath}" "{elf}"') != 0:
            return False
    else:
        if os.system(f'patchelf --remove-rpath "{elf}"') != 0:
            return False
        if os.system(f'patchelf --set-interpreter \'\' "{elf}"') != 0:
            return False
    return True


def patch_elf_from_stdlibc(elf: str, std_libc: str) -> bool:
    std_libc = os.path.join(glibc_all_in_one, std_libc)
    if os.path.isdir(std_libc):
        return patch_elf(elf, std_libc, os.path.join(std_libc, 'ld-linux-x86-64.so.2'))
    else:
        return False


def init_elf_with_libc(
        elf_path: str, 
        libc_path: str, 
        ld_path: str = '', 
        force: bool = False, 
        manual: bool = False):
    """ It is used to init the elf. It does two things: 
            - Give the elf execution permissions
            - Identify the glibc version according to the argument `libc_path` and patchelf automatically.
        When the elf already has runpath, or `libc_path` is empty, this function will return directly.
            
    Args:
        elf_path (str): the path of elf
        libc_path (str): the path of libc to patch
        ld_path (str, optional): path of ld. Defaults to None.
        force (bool, optional): whether to do `init_elf_with_libc` forcefully. Defaults to False.
        manual (bool, optional): whether to patchelf using menu. Defaults to False.
    """

    if not os.path.exists(elf_path):
        return

    elf = path2ELF(elf_path)

    if(elf.runpath != None):
        # if we have set runpath, then return
        if glibc_all_in_one in elf.runpath.decode():
            cct.std_libc = os.path.basename(elf.runpath.decode())
        if not force and not manual:
            return
    
    if not os.access(elf_path, os.X_OK):
        elf_X(elf_path)

    if (libc_path == '' or libc_path == None) and manual == False:
        return
    
    std_libc = None

    if manual == True:
        std_libc = choose_glibc_from_std()

    if std_libc == None:
        try:
            std_libc = find_std_glibc(libc_path)
        except libcNotExistError as e:
            print(f'[{COLOR_REDX}-{COLOR_RESET}] init_elf_with_libc(): {e.__str__()}')
            return

    if std_libc != None:
        std_libc = std_libc[6:-3]
        if patch_elf_from_stdlibc(elf_path, std_libc):
            cct.std_libc = std_libc
            print(f'[{COLOR_GREENX}+{COLOR_RESET}] Patchelf success!')
        else:
            print(f'[{COLOR_REDX}-{COLOR_RESET}] init_elf_with_libc(): Patchelf fail! Please check your glibc_all_in_one!')
    else:
        if ld_path == '' and os.path.exists('./ld-linux-x86-64.so.2'):
            ld_path = './ld-linux-x86-64.so.2'
            cct.interpreter = ld_path
            elf_X(ld_path)

        if ld_path != '':
            print(f'[{COLOR_GREENX}+{COLOR_RESET}] Use customized patchelf.')
            if patch_elf(elf_path, os.path.dirname(libc_path), ld_path):
                print(f'[{COLOR_GREENX}+{COLOR_RESET}] Patchelf success!')
            else:
                print(f'[{COLOR_REDX}-{COLOR_RESET}] init_elf_with_libc(): Patchelf fail!')
        else:
            print(f'[{COLOR_REDX}-{COLOR_RESET}] init_elf_with_libc(): Cannot find a glibc to patch and no ld was given!')

