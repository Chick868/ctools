from pwn import *
from typing import Literal, Union

import pwnlib.tubes.remote as rtube
import pwnlib.tubes.process as ptube


""" ARGS FOR CONN_CONTEXT_TYPE """
USE_PROXY = 'USE_PROXY'       # use proxyschains, if use REMOTE
PRE_LOAD = 'PRE_LOAD'         # use preload and need ld_rpath, if use LOCAL
SECCOMP_DUMP = 'SECCOMP_DUMP' # use seccomp-tools dump
SSL = 'SSL'                   # use SSL in remote
SHELL = 'SHELL'               # set argument 'shell' to True

class ConnContextType:
    def __init__(self) -> None:
        self.std_libc: Union[str, None] = None # std_libc from rpath 
        self.host: str = ''
        self.port: int = 0
        self.target: Literal['REMOTE', 'LOCAL'] = 'LOCAL'
        self.interpreter: str = '' # ld_path
        self.preload: Union[list, None] = None # LD_PRELOAD
        self.args: list = []
        self.elf_path: str = ''
        self.libc_path: str = ''
        self.libs = None # libs in fast_libs

    
    def __call__(self, **kwargs) -> None:
        self.update(**kwargs)
        

    def update(self, **kwargs) -> None:
        apath = kwargs.get('apath')
        if apath is not None and apath != '':
            chwsp(apath)
            kwargs.pop('apath')
            success('Entering directory %s' % os.getcwd())
        
        args = kwargs.get('args')
        if args is not None and isinstance(args, list):
            self.append_args(args)

        for k, v in kwargs.items():
            setattr(self, k, v)


    def append_args(self, args):
        if not hasattr(self, 'args'):
            self.args = []
        self.args += [arg for arg in args]


    def init(self, force: bool = False, manual: bool = False):
        from .elf_init import init_elf_with_libc
        # add mode +x to elf and patchelf
        init_elf_with_libc(self.elf_path, self.libc_path, self.interpreter, 
                           force=force, manual=manual)


cct = ConnContextType()

from .utils import *

def GNOME_TERMINAL():
    context(terminal=['gnome-terminal', '-x', 'sh', '-c'])


def TMUX_TERMINAL():
    context(terminal=['tmux', 'splitw', '-h', '-F' '{pane_pid}', '-P', '-l', '135'])


# rm core dump
def rm_core():
    os.system('rm ./core.* > /dev/null 2>&1')


def _conn(
        host: str, 
        port: int, 
        elf: Union[str, list], 
        target: Literal['REMOTE', 'LOCAL'], 
        preload: Union[None, str, list] = None, 
        args: list = []
        ) -> Union[rtube.remote, ptube.process]:
    """ Get connection pipe according the parameters. Auto new remote or process.

    Args:
        host (str): host ip or domain
        port (int): target port
        elf (Union[str, list]): used as argv[0], valid when LOCAL.
        target (Literal['REMOTE', 'LOCAL']): LOCAL or REMOTE.
        preload (Union[None, str, list], optional): set envirment of 'LD_PRELOAD'.
        args (list, optional): extended args. Defaults to [].

    Raises:
        ctoolsError: when operation invaild.

    Returns:
        Union[pwnlib.tubes.remote.remote, pwnlib.tubes.process.process]: the pipe

    Examples:
        io = conn('127.0.0.1', 9999, './pwn', 'REMOTE', preload = ['./libc.so.6'], args = [USE_PROXY])
    """
    pre_load = False
    proxy = False
    seccomp = False
    ssl = False
    shell = False
    
    for arg in args:
        if arg == PRE_LOAD: pre_load = True
        elif arg == USE_PROXY: proxy = True
        elif arg == SECCOMP_DUMP: seccomp = True
        elif arg == SSL: ssl = True
        elif arg == SHELL: shell = True

    if target == 'REMOTE':
        if proxy and 'proxy_child' not in sys.argv:
            os.system('proxychains %s proxy_child' % ''.join([i + ' ' for i in sys.argv]))
            exit(0)
        else:
            return remote(host, port, ssl=ssl)
    elif target == 'LOCAL':
        argv = []
        env = {}

        if isinstance(preload, list):
            preload = ''.join([lib + ':' for lib in preload]) 
            if len(preload) != 0:
                preload = preload[:-1]
        
        if pre_load and preload is not None:
            ll = preload.split(':')
            for i in ll:
                assert i.startswith(('./', '../', '/')), 'path not correct'

        if seccomp:
            argv += ['seccomp-tools', 'dump', '-c']
            if pre_load:
                if preload is None:
                    raise ctoolsError('conn: preload expects not null.')
                argv.append(f'LD_PRELOAD={preload}')
        elif pre_load:
            if preload is None:
                raise ctoolsError('conn: preload expects not null.')
            env['LD_PRELOAD'] = preload
        
        if isinstance(elf, list):
            argv += elf
        else:
            argv.append(elf)
        
        return process(argv, env=env, shell=shell)
    else:
        raise ctoolsError(f'conn: target expect ROMOTE or LOCAL, but got {target}')
            

def conn(target = None, argv = None, **kwargs) -> Union[rtube.remote, ptube.process]:
    if len(kwargs) != 0:
        cct.update(**kwargs)
    if target is None:
        target = cct.target
    if argv is None:
        argv = cct.elf_path
    return _conn(
        cct.host,
        cct.port,
        argv,
        target,
        cct.preload,
        cct.args
    )


import atexit
from .gdb import debug_fini

def exp_fini():
    if cct.target == 'LOCAL':
        # rm_core()
        debug_fini()

atexit.register(exp_fini)