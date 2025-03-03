# XXTEA
## 整体梳理
作为 XTEA 的升级版，XXTEA 和 XTEA 一点不像。在运算上改变很大
```c++
do 
{
    sum += delta;
    e = (sum >> 2) & 3;
    for (p = 0; p < n - 1; ++p)
    {
        y = value[p + 1];
        value[p] += (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)));
        z = value[p];
    }
    y = value[0];
    value[n - 1] += (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)));
    z = value[n - 1];
}
while (--num_rounds);
```

## 特点梳理
### 特点一
变量：用一个长度为 4 的 key 数组加密/解密一个长度为 2 的 value 数组。其中有一个 sum 临时变量也会在每轮加密/解密时自增/自减。

### 特点二
特征值：sum 每次自增/自减的值是个常量 0x9e3779b9/2654435769

### 特点三
运算：
```c
(((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)));
```