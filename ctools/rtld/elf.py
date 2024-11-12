from ..pack import *

"""
typedef struct
{
  Elf64_Sxword	d_tag;			/* Dynamic entry type */
  union
    {
      Elf64_Xword d_val;		/* Integer value */
      Elf64_Addr d_ptr;			/* Address value */
    } d_un;
} Elf64_Dyn;
"""
def Elf64_Dyn(d_tag: int = 0, d_un: int = 0):
    return p64(d_tag) + p64(d_un)
    
"""
typedef struct
{
  Elf64_Word	st_name;		/* Symbol name (string tbl index) */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char st_other;		/* Symbol visibility */
  Elf64_Section	st_shndx;		/* Section index */
  Elf64_Addr	st_value;		/* Symbol value */
  Elf64_Xword	st_size;		/* Symbol size */
} Elf64_Sym;
"""
def Elf64_Sym(st_name = 0, st_info = 0, st_other = 0,
              st_shndx = 0, st_value = 0, st_size = 0):
    return p32(st_name) + p8(st_info) + p8(st_other) + p16(st_shndx) + \
            p64(st_value) + p64(st_size)

"""
typedef struct
{
  Elf64_Addr	r_offset;		/* Address */
  Elf64_Xword	r_info;			/* Relocation type and symbol index */
  Elf64_Sxword	r_addend;		/* Addend */
} Elf64_Rela;
"""
def Elf64_Rela(r_offset = 0, r_info = 0, r_addend = 0):
    return p64(r_offset) + p64(r_info) + p64(r_addend)