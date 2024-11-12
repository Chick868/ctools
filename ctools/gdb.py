from .conn import cct, ptube
from .utils import *

from pwn import *

glibc_source = os.getenv('GLIBC_SOURCE')

def udebug(io: ptube.process, script: str = '', load: bool = True, source: bool = False):
    """ User mode debug. Auto load libc symbols and source code

    Args:
        io (ptube.process): io pipe
        script (str, optional): debug script. Defaults to ''.
        load (bool, optional): load libc symbols. Defaults to True.
        source (bool, optional): load libc source code. Defaults to False.
    """
    if not isinstance(io, ptube.process):
        return
    if load:
        if cct.std_libc is None:
            print(f'[{COLOR_REDX}-{COLOR_RESET}] udebug(): std-libc not found. (symbol)')
        else:
            debug_path = os.path.join(glibc_all_in_one, cct.std_libc)
            debug_path = os.path.join(debug_path, '.debug')
            with open('./.tmp_libc_symbol_path', 'w') as f:
                f.write(debug_path)

    if source:
        version = None
        from_rpath = False

        if cct.std_libc is None and ELF(cct.elf_path).runpath is None:
            # use system GNU version
            version = '2.39'

        elif cct.std_libc is None:
            print(f'[{COLOR_REDX}-{COLOR_RESET}] udebug(): std-libc not found. (source)')
        else:
            version = cct.std_libc[:4]
            from_rpath = True
        
        if version is not None:
            if version not in ['2.23', '2.27', '2.31', '2.35', '2.39']:
                print(f'[{COLOR_REDX}-{COLOR_RESET}] udebug(): Version not support (source).')
            else:
                head = 'directory %s/%s' % (glibc_source, 'glibc-' + version)
                if from_rpath:
                    head += '/debug'
                script = head + '\n' + script
                success('Using source code %s' % (head[10:]))
    
    gdb.attach(io, gdbscript=script)


def debug_fini():
    os.system('rm ./.tmp_libc_symbol_path > /dev/null 2>&1')