## 介绍

ctools 是一个用于 CTF 竞赛中 pwn 方向的工具库。

ctools 包含了两个部分：

- 基于 python 的 ctools 工具库，也是本项目的主要部分。通过在 python 中导入 ctools，你可以
  - 根据指定的 libc 自动 patchelf；
  - 使用一些在 pwn 中可能对你有帮助的工具；
  - 将 exp 和题目的各种文件分离，这样你可以构建一个更加简洁的工作区；
  - 提供各种便利的启动方式，包括使用`PRE_LOAD`环境变量加载多个共享库、使用`seccomp-tools`启动（用于沙箱加载的地方必须通过 pwntools 交互才能到达时）、使用 proxychains 代理等；
  - gdb 自动加载 libc 符号或 libc 源码调试；
  - ...
- 基于 vscode 的 Snippets 代码块功能，可以快速生成一些常用代码块和 payload

## 快速开始

要在 python 使用 ctools，我们可以简单地将 ctools 文件夹软链接到当前 python3 的`site-packages`里。我们可以用命令`python3 -m site`查看`site-packages`目录，如果不存在我们需要先创建，然后软链接到`site-packages`目录下即可。

要使用自定义代码块（如下图示例），我们要将`snippets`文件夹下的文件复制到 vscode 的全局 snippets 文件夹里。如果不知道该文件夹在哪，我们可以 vscode 中左下角的设置中找到`snippets`选项，然后新建一个全局的 snippets 文件，然后根据这个新建文件的位置即可找到，一般会在`~/.config/Code/User/snippets`里。

![show](./README.assets/show.gif)

在启动前，我们还需要进行一些简单的配置。

打开`ctools/__init__.py`，看到`MANUAL CONFIG`块，依次设置`glibc-all-in-one`，`libs`，`glibc-source`，`workspace`，`exp`的路径。

其中前 3 个在 ctools 根目录已经配置好了，分别代表

1. `glibc-all-in-one`的路径，用于 patchelf 和 debug 符号加载。**由于文件夹较大，在仓库里不再上传，有需要可以到 [release 页面](https://github.com/Chick868/ctools/releases)下载完整版本。**
2. `libs`的路径，用于 auto patch 时的快速 libc 库
3. `glibc-source`，不同版本 glibc 的源码，用于进行源码调试。目录结构已经建好，但因为文件过大，所以这里不再上传，需要的请自行寻找资源。

你可以保持上面的 3 个路径不变，如果你想使用其他地方的自定义目录，简单修改即可，或是设置软链接到其他地方即可。

剩下的两个分别是

1. `workspace`，指向题目附件的文件夹
2. `exp`，指向 exp 代码的文件夹

这里的目的是将题目附件和 exp 分离，看起来不会那么繁杂。如果向使用同一文件夹，也是直接设置成一个相同文件夹即可。

指定一个 workspace 可以将不同题目隔离开来，看起来会舒服一些。在后面我们可以看到我们可以设置`apath`参数来选定 workspace 中的一个文件夹，即`append path`

```
workspace
├── babyheap
│   ├── libc.so.6
│   ├── pwn
│   └── pwn.i64
├── kno
│   ├── boot.sh
│   ├── bzImage
│   ├── extract-vmlinux.sh
│   ├── g1
│   ├── init
│   ├── _rootfs.cpio
│   ├── rootfs.cpio
│   ├── test.ko
│   ├── test.ko.i64
│   └── vmlinux
└── vm
    ├── libc-2.31.so
    ├── vm
    └── vm.i64
```

最后，如果我们要使用 gdb 自动加载符号的功能，我们需要手动修改 pwndbg 安装目录下的`pwndbg/gdbinit.py`，在最后添加如下代码

```python
COLOR_GREEN = "\033[32m"
COLOR_RED = "\033[31m"
COLOR_RESET = "\033[0m"
import gdb
import os

if(os.path.exists('./.tmp_libc_symbol_path')):
    with open('./.tmp_libc_symbol_path', 'r') as f:
        debug_path = f.read()
        print(COLOR_GREEN + '[+] set debug-file-directory to {}'.format(debug_path) + COLOR_RESET)
        gdb.execute('set debug-file-directory {}'.format(debug_path))
```

****



现在我们就基本完成了配置。接下来我们就可以开始 exp 的编写了。这里推荐我使用的一个模版

```python
#! /usr/bin/env python3.8
from pwn import *
from ctools import *

### CONFIG ========================================

context(os="linux", arch="amd64")

elf_path = './pwn'
libc_path = './libc.so.6'

config = {
    'host': '127.0.0.1',    # remote host
    'port': 9999,           # remote port
    'target': 'LOCAL',      # process if LOCAL, remote if REMOTE
    'args': [],             # args, more information in `ctools/conn.py`
    'preload': [libc_path], # set env `LD_PRELOAD`, we can load multiple shared library
    'elf_path': elf_path,   # elf path
    'libc_path': libc_path, # libc path
    'apath': './babyheap',  # append path to workspace
}

TMUX_TERMINAL() # use tmux terminal
DEBUG = lambda s='', l=True, m=False: udebug(io, script=s, load=l, source=m)

cct(**config)  # update config
cct.init()     # chmod +x and auto patchelf

### CONFIG END ===================================

io = conn() # get io pipe
# context.log_level = "debug"

elf = ELF(elf_path)
libc = ELF(libc_path, checksec=False)

def exp():
	# start your exp here
    
    pass

if __name__ == '__main__':
    exp()
    io.interactive()
```

切换远程和本地，修改 config 参数`target`为`REMOTE`或`LOCAL`即可；如果我们不想使用 auto patch，简单注释`cct.init()`即可。

获取 io 管道，我们使用代码

```python
io = conn()
```

在启动的程序是一个非 elf 文件，例如脚本时，我们可以设置 config 参数 args `SHELL`，并修改

```python
io = conn(argv='./start.sh')
```

即可。不过这时需要我们手动给 start.sh 赋可执行权限

## 高级

args 参数：

```python
USE_PROXY = 'USE_PROXY'       # use proxyschains, if use REMOTE
PRE_LOAD = 'PRE_LOAD'         # use preload and need ld_rpath, if use LOCAL
SECCOMP_DUMP = 'SECCOMP_DUMP' # use seccomp-tools dump
SSL = 'SSL'                   # use SSL in remote
SHELL = 'SHELL'               # set argument 'shell' to True
```

> 如果我们需要使用代理，设置参数`USE_PROXY`，使用的实际上是`proxychains`命令。请确保你的系统已经安装`proxychains`并正确设置代理。

> 参数`PRE_LOAD`表示我们设置了环境变量`PRE_LOAD`，手动指定共享库。共享库指定使用 config 列表参数`preload`，列表里的每一个元素是一个以`./`，`../`或`/`开头的字符串。例如我们可以设置
>
> ```python
> preload = ['./libc.so.6', './libseccomp.so.2']
> ```



**更多功能请查看`ctools/doc`**