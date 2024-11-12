# Ctools 文档

ctools 主要包含以下模块：

- [conn](#conn) - ctools 核心模块。该模块主要完成管道创建，类`cct`存储着 ctools 的各种状态，并完成 ctools 的析构工作。
- [functions](#functions) - 定义了一些用户可使用的函数，方便一些操作
- elf_init - 初始化 elf 文件，包括 change mode 和 patchelf
- gdb - 自动加载 libc 符号和源码
- pack - 定义了 p64, p32, u64 等，~~拒绝警告下划线~~。除此之外还定义了 p64x 这些打包函数，可以自动处理负数和溢出的情况。
- LibcSearcher - 重写 LibcSearcher 库，修复查找的 bug，并提供更简单的 api
- utils - 内部工具类
- **rtld** - 定义了一些 link_map 相关的工具
- **[kernel](#kernel)** - 用于 kernel 利用，主要功能是本地或远程的 elf 传输、各种初始化工作（自动解包、编译、打包等）。目前尚在测试阶段，不建议使用
- **[snippets](#snippets)** - 自定义代码块



## conn

待补充

## functions

待补充，可以自行查看源码注释，应该还挺详细的，吧

## snippets

**orw**

> 这些板子都是读`/flag`的 0x50 字节

|     指令      |                      作用                      |
| :-----------: | :--------------------------------------------: |
|     `orw`     |                 经典 orw 板子                  |
|   `orw_iov`   |            `openat, readv, writev`             |
| `orw_openat2` |            `openat2, readv, writev`            |
| `orw_socket`  | `socket, sendfile`发送到一个指定的 [host:port] |

**交互模版**

|     指令      |                       作用                       |
| :-----------: | :----------------------------------------------: |
|     `sl`      |                `io.sendline($1)`                 |
|     `sla`     |          `io.sendlineafter(b'$1', $2)`           |
|     `sd`      |                  `io.send($1)`                   |
|     `sa`      |            `io.sendafter(b'$1', $2)`             |
|     `rcv`     |                   `io.recv()`                    |
|     `rcu`     |            `io.recvuntil(b'$1', $2)`             |
| `l64` / `l32` |       `u64(io.recv(6).ljust(8, b'\x00'))`        |
|     `r64`     | `io.recvuntil(b'0x')` and `int(io.recv(12), 16)` |

**pwntools 常用代码块**

|      指令      |                           作用                           |
| :------------: | :------------------------------------------------------: |
|     `scs`      |                 `success(f'{$1 = :#x}')`                 |
|     `gots`     |                     `elf.got['$1']`                      |
|     `plts`     |                     `elf.plt['$1']`                      |
|     `lsym`     |                   `libc.symbol['$1']`                    |
|     `psym`     |                    `elf.symbol['$1']`                    |
|   `lsearch`    |               `libc.search($1).__next__()`               |
|     `i2b`      |                    `str($1).encode()`                    |
|    `newsec`    |                         代码分区                         |
| `print_newsec` | 打印时分区`print(f\"\\n\\n#{' $1 '.center(70, '=')}#\")` |
|  `heap_menu`   |                          堆菜单                          |

**常用 payload**

|     指令      |                             作用                             |
| :-----------: | :----------------------------------------------------------: |
|    `srop`     |                        标准 SROP 板子                        |
| `ret2csu_r15` |             ret2csu 板子，以 r15 寄存器进行调用              |
|   `reveal`    |         2.32 后加入的堆指针加密`(addr >> 12) ^ ptr`          |
|   `ret2dl`    |                    ret2dl 伪造的 linkmap                     |
|   `banana`    | House of Banana，伪造 4 个 linkmap，需要提前修改`_rtld_global`的指针 |

## kernel

自用的 kernel 的板子，主要用途有自动获取 debug 脚本；自动解包、编译、打包、启动；自动获取内核的基地址和模块基地址

> 目前尚在测试阶段，不保证能用

```python
#! /usr/bin/env python3
from pwn import *
from ctools import *
from ctools.kernel import *
import atexit

### CONFIG =======================================

context(os="linux", arch="amd64")
# context.log_level = "debug"
context.newline = b'\r\n'

kernel_module = './test.ko'
boot = './boot.sh'
rootfs = 'rootfs.cpio'

config = {
    'host': '',
    'port': 0,
    'target': 'LOCAL',
    'elf_path': boot, # boot script here
    'args': [SHELL],
}

# used in local debug
module_name = 'test'
module_base = 0
kernel_base = 0

### append
### `cat /proc/kallsyms > /tmp/kallsyms`
### `cat /sys/module/{module_name}/sections/.text > /tmp/.text`
def gen_debug_prefix():
    debug_script = [
        f'target remote :1234',
        f'add-symbol-file {kernel_module} {module_base:#16x}',
        f'add-symbol-file ./vmlinux {kernel_base:#16x}',
    ]
    debug_script = ''.join([line + '\n' for line in debug_script])
    with open('.gdb_prefix', 'w') as f:
        f.write(debug_script)
    def clean_tmp():
        os.system('rm ./.gdb_prefix 2>/dev/null')
    atexit.register(clean_tmp)


chwsp('./kno')
cct(**config)

os.system(f'chmod +x {boot}')

### CONFIG END ===================================

if cct.target == 'LOCAL':
    local_trans(cpio=rootfs)

io = conn()
elf = ELF(kernel_module)

if cct.target == 'REMOTE':
    remote_trans(io)

# get kernel and module base
if cct.target == 'LOCAL':
    io.sendlineafter(b'/ $', b'cat /tmp/.text')
    io.recvuntil(b'0x')
    module_base = int(io.recv(16), 16)
    io.sendlineafter(b'/ $', b'cat /tmp/kallsyms | grep \'_text\'')
    kernel_base = int(io.recvuntil(b' T _text', drop=True)[-16:], 16)
    io.recvuntil(b'/ $')
    print(f"\n\n#{' DEBUG INFO '.center(70, '=')}#")
    print(f'[{COLOR_REDX}DEBUG{COLOR_RESET}] ' + f'{module_base = :#x}')
    print(f'[{COLOR_REDX}DEBUG{COLOR_RESET}] ' + f'{kernel_base = :#x}')
    gen_debug_prefix()
    

def exp():

    pass


if __name__ == '__main__':
    exp()
    io.interactive()

```
