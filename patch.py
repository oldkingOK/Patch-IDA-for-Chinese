# https://www.capstone-engine.org/lang_python.html

import pefile
from capstone import *

# 加载PE文件
pe = pefile.PE('./ida.dll')
# capstone反编译器 初始化
MODE = Cs(CS_ARCH_X86, CS_MODE_64)

def get_func_code(func2_addr, f):
    f.seek(func2_addr)
    prev = 0
    code = b""
    while True:
        b = f.read(1)
        code += b
        if b == b'\xCC' and prev == b'\xCC':
            break
        prev = b
    return code

def dism_func(func2_addr, f):
    for i in MODE.disasm(get_func_code(func2_addr, f), 0):
        print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")

# 从导出表找到函数的地址，并计算出应该patch的地址
print("BaseOfCode: ", hex(pe.OPTIONAL_HEADER.BaseOfCode))
print("BaseOfCode: ", hex(pe.OPTIONAL_HEADER.SizeOfHeaders))

BaseOfCode = pe.OPTIONAL_HEADER.BaseOfCode
SizeOfHeaders = pe.OPTIONAL_HEADER.SizeOfHeaders

for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if b"calc_c_cpp_name" == exp.name:
        print(f'Name: {exp.name}, Address: {hex(exp.address)}, File Address: {hex(exp.address - BaseOfCode + SizeOfHeaders)}')
        start_addr = exp.address - BaseOfCode + SizeOfHeaders
        break

with open('./ida.dll', 'rb') as f:
    f.seek(start_addr)
    code = get_func_code(start_addr, f)

    for i in MODE.disasm(code, 0):
        if i.mnemonic == "call":
            # 0x20:   call    0xffffffffffffaa50
            print(f"call addr is {hex(start_addr + (int(i.op_str, 16) - 2**64))}")
            func2_start_addr = start_addr + (int(i.op_str, 16) - 2**64)
            break
    
    code = get_func_code(func2_start_addr, f)

    nop_addr = []
    for i in MODE.disasm(code, 0):
        if i.mnemonic == "mov" and "0x5f" in i.op_str:
            print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
            nop_addr += [func2_start_addr + i.address]

print([hex(i) for i in nop_addr])

import shutil
shutil.copyfile('./ida.dll', './ida.dll.bak')

# 打开文件
with open('ida.dll', 'rb+') as f:
    # 定位到第10个字节
    for addr in nop_addr:
        f.seek(addr)
        f.write(b'\x90\x90\x90')

    print("Patch success!, checking the result")

with open('ida.dll', 'rb') as f:
    dism_func(start_addr, f)
    print("=====================================================")
    dism_func(func2_start_addr, f)