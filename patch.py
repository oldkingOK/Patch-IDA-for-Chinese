# https://www.capstone-engine.org/lang_python.html

import pefile
from capstone import *

# 加载PE文件
pe = pefile.PE('./ida.dll')

# 0x1BF600 是函数在文件中的偏移量
# 0x1c0200 是函数在dll中的偏移量
# 差个 0xc00

# 查看导出表
print("ImageBase: ", hex(pe.OPTIONAL_HEADER.ImageBase))
print("BaseOfCode: ", hex(pe.OPTIONAL_HEADER.BaseOfCode))
print("BaseOfCode: ", hex(pe.OPTIONAL_HEADER.SizeOfHeaders))

ImageBase = pe.OPTIONAL_HEADER.ImageBase
BaseOfCode = pe.OPTIONAL_HEADER.BaseOfCode
SizeOfHeaders = pe.OPTIONAL_HEADER.SizeOfHeaders

for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if b"calc_c_cpp_name" == exp.name:
        print(f'Name: {exp.name}, Address: {hex(exp.address)}, File Address: {hex(exp.address - BaseOfCode + SizeOfHeaders)}')
        start_addr = exp.address - BaseOfCode + SizeOfHeaders
    
    # 下一个函数的地址，用于确定函数的结束位置
    if b"calc_number_of_children" == exp.name:
        print(f'Name: {exp.name}, Address: {hex(exp.address)}, File Address: {hex(exp.address - BaseOfCode + SizeOfHeaders)}')
        end_addr = exp.address - BaseOfCode + SizeOfHeaders

with open('./ida.dll', 'rb') as f:
    f.seek(start_addr)
    code = f.read(end_addr - start_addr)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(code, 0):
        if i.mnemonic == "call":
            # 0x20:   call    0xffffffffffffaa50
            print(f"call addr is {hex(start_addr + (int(i.op_str, 16) - 2**64))}")
            func2_start_addr = start_addr + (int(i.op_str, 16) - 2**64)
            break
    
    f.seek(func2_start_addr)
    prev = 0
    code = b""
    while True:
        b = f.read(1)
        code += b
        if b == b'\xCC' and prev == b'\xCC':
            print(f"find the end of the function")
            break
        prev = b

    nop_addr = []
    for i in md.disasm(code, 0):
        if i.mnemonic == "mov" and "0x5f" in i.op_str:
            print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
            nop_addr += [func2_start_addr + i.address]
        # print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")

print([hex(i) for i in nop_addr])

import shutil
shutil.copyfile('./ida.dll', './ida.dll.bak')

# 打开文件
with open('ida.dll', 'rb+') as f:
    # 定位到第10个字节
    for addr in nop_addr:
        f.seek(addr)
        f.write(b'\x90\x90\x90')

    print("Patch success!")