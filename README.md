# IDA 中文函数显示自动Patch

## 使用

```sh
python -m venv .venv
# activate
pip install -r requirements.txt
python patch.py ida.dll
python patch.py ida64.dll
```

## 另外

还需要修改 `IDA_Pro\cfg\ida.cfg` 才能正常显示

```c
NameChars =
        "$?@"           // asm specific character
        "_0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz",
        // This would enable common Chinese characters in identifiers:
        // Block_CJK_Unified_Ideographs,
        CURRENT_CULTURE;
```

把 `Block_CJK_Unified_Ideographs` 的注释取消掉即可

## 原理

参考：[IDA7.5支持中文函数命名的办法 - 吾爱破解](https://www.52pojie.cn/thread-1414525-1-1.html)

找到函数 calc_c_cpp_name，其会call一个函数，然后根据反汇编，找到对应的赋值 '_' 的语句，NOP掉