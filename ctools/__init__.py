# -*- coding: utf-8 -*-
"""
@Name    :  ctools
@Time    :  2024/11/12
@Author  :  Chick
@Version :  v0.5.0
@Desc    :  Tools used for ctf.
"""

import os
 
CTOOLS_ROOT_DIR = os.path.dirname(__file__)
os.environ['CTOOLS_ROOT_DIR'] = CTOOLS_ROOT_DIR


#-------------------------- MANUAL CONFIG --------------------------#

# path to glibc-all-in-one, used to patch and debug
DEFAULT_GLIBC_ALL_IN_ONE = os.path.join(CTOOLS_ROOT_DIR, 'glibc-all-in-one/libs')
# a small but commonly used library
DEFAULT_LIBS = os.path.join(CTOOLS_ROOT_DIR, 'libs')
# glibc source code path
DEFAULT_GLIBC_SOURCE = os.path.join(CTOOLS_ROOT_DIR, 'glibc-source')
# the path of workspace
DEFAULT_WORKSPACE = "/path/to/your/workspace"
# exp directory
DEFAULT_EXP_DIR = '/path/to/your/exp'

#--------------------------- CONFIG END ---------------------------#


if os.getenv('GLIBC_ALL_IN_ONE') is None:
    os.environ['GLIBC_ALL_IN_ONE'] = DEFAULT_GLIBC_ALL_IN_ONE
if os.getenv('CTOOLS_LIBS') is None:
    os.environ['CTOOLS_LIBS'] = DEFAULT_LIBS
if os.getenv('CTOOLS_WORKSPACE') is None:
    os.environ['CTOOLS_WORKSPACE'] = DEFAULT_WORKSPACE
if os.getenv('GLIBC_SOURCE') is None:
    os.environ['GLIBC_SOURCE'] = DEFAULT_GLIBC_SOURCE
if os.getenv('CTOOLS_EXP_DIR') is None:
    os.environ['CTOOLS_EXP_DIR'] = DEFAULT_EXP_DIR

from .pack import *
from .utils import *
from .conn import *
from .elf_init import *
from .LibcSearcher import *
from .functions import *
from .gdb import *
from .rtld import *
from . import kernel

# we change pwd first
os.chdir(os.getenv('CTOOLS_WORKSPACE'))
success('Now working path: %s' % os.getcwd())