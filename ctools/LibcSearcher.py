from pwn import *
from typing import Union, overload

from .utils import *

def create_symbols(libc_path: str):
    libc = path2ELF(libc_path)
    with open(libc_path + '.symbols', 'w') as f:
        for k, v in sorted(libc.symbols.items(), key=lambda x: x[1]):
            f.write(k + ' ')
            f.write((f'{v:016x}') + '\n')


def create_buildid(libc_path:str):
    libc = path2ELF(libc_path)
    with open(libc_path + '.buildid', 'w') as f:
        f.write(''.join(f'{byte:02x}' for byte in libc.buildid))


def get_glibc_info(libc_path: str):
    info('Trying to get some infomation of the libc...')
    sys.stdout.write('>>> \033[1;31m')
    os.system(f'strings {libc_path} | grep -m1 GNU')
    sys.stdout.write('\033[0m')

@overload
def LibcSearcher(cond: dict, libc_path: str = None) -> Union[str, None]:
    ...

@overload
def LibcSearcher(cond: dict, elf: bool = True, libc_path: str = None) -> Union[elf.ELF, None]:
    ...


def LibcSearcher(cond: dict = None, elf: bool = False, libc_path: str = None) -> Union[str, elf.ELF, None]:
    """ Search libc from `libs` directory, return the result or None if not found

    Args:
        cond (dict, optional): key-value pair of function and address
        elf (bool, optional): return ELF if True. Default to False
        libc_path (str, optional): if we already have libc, then we can simply compare buildID. 

    Returns:
        elf.ELF or str or None: the result

    Examples:
        libc = LibcSearcher({'puts': 0xed0, 'read': 0x980}, elf=True)
        LibcSearcher(libc_path='./libc.so.6')
    """
    res_list = []
    patterns = []
    std_libs = walk_libs()

    # if libc_path is not None, search by buildID
    if libc_path != None:
        libc = path2ELF(libc_path)
        buildid = ''.join(f'{byte:02x}' for byte in libc.buildid)
        for name in std_libs:
            std_lib_path = os.path.join(libs, name)
            if not os.path.exists(std_lib_path + '.buildid'):
                create_buildid(std_lib_path)
            with open(std_lib_path + '.buildid', 'r') as f:
                std_buildid = f.read()
            if std_buildid.__eq__(buildid):
                print(f'[{COLOR_GREENX}+{COLOR_RESET}] Glibc version is: \033[32m{name}\033[0m')
                if elf == False:
                    return name
                return path2ELF(std_lib_path)
        print(f'[{COLOR_REDX}-{COLOR_RESET}] LibcSearcher(): Glibc version not found (BuildID)!')

    if cond is None:
        return None

    # search by symbols
    for k, v in cond.items():
        patterns.append(re.compile('%s .*%03x\n' % (k, v & 0xfff)))

    for name in std_libs:
        std_lib_path = os.path.join(libs, name)
        if not os.path.exists(std_lib_path + '.symbols'):
            create_symbols(std_lib_path)
        with open(std_lib_path + '.symbols', 'r') as f:
            funcs = f.read()
        if all([re.search(i, funcs) for i in patterns]):
            res_list.append(name)

    # handle results
    if len(res_list) == 1:
        res = res_list[0]
    elif len(res_list) == 0:
        print(f'[{COLOR_REDX}-{COLOR_RESET}] LibcSearcher(): Glibc version not found (CheckList)!')
        if libc_path != None:
            get_glibc_info(libc_path)
        return None
    else:
        info('Multiple glibcs meet the conditions.')
        if libc_path != None:
            get_glibc_info(libc_path)
        print('--------------------------------------')
        for i in range(res_list.__len__()):
            print(f'[{i + 1}] {res_list[i]}')
        print('--------------------------------------')
        choice = int(input('Please input the glibc you want to choose: '))
        res = res_list[choice - 1]
    print(f'[{COLOR_GREENX}+{COLOR_RESET}] Glibc version is: \033[32m{res}\033[0m')
    if elf == True:
        return path2ELF(os.path.join(libs, res))
    return res