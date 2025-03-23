# AES
## 整体梳理
初始化密钥，每轮密钥的生成只与上一轮密钥有关，可以直接全都生成出来再加密，或者边加密边生成，详见`static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)`。

加密分为三个基本操作：矩阵中的值替换为 S 盒中的值、函数将矩阵中的行向左循环移位、对矩阵的列进行混合。大部分为异或运算。详见`static void Cipher(state_t* state, const uint8_t* RoundKey)`

IV 作为扰动，在不同模式（CDC 、ECB 、 CTR）， IV 的处理方式不同，核心思想是与待加密值进行异或。可以看成一个“最简版”的 key。

## 特点梳理

### 特点一
key 长度：16、24、32 字节，不同长度的字节数将 AES 划分为 128 192 256 三个版本，并且影响加密的轮数：10 12 14
### 特点二
iv 长度：16 字节
### 特点三
4 * 4 矩阵：加密的单位是 4 * 4 矩阵，每 16 个字节为一组，按 4 * 4 矩阵统一操作。
### 特点四
交换运算：
```c
// 将第一行向左循环移位 1 列
temp           = (*state)[0][1];
(*state)[0][1] = (*state)[1][1];
(*state)[1][1] = (*state)[2][1];
(*state)[2][1] = (*state)[3][1];
(*state)[3][1] = temp;

// 将第二行向左循环移位 2 列
temp           = (*state)[0][2];
(*state)[0][2] = (*state)[2][2];
(*state)[2][2] = temp;

temp           = (*state)[1][2];
(*state)[1][2] = (*state)[3][2];
(*state)[3][2] = temp;

// 将第三行向左循环移位 3 列
temp           = (*state)[0][3];
(*state)[0][3] = (*state)[3][3];
(*state)[3][3] = (*state)[2][3];
(*state)[2][3] = (*state)[1][3];
(*state)[1][3] = temp;
```
### 特点五
大量异或运算：
```c
t   = (*state)[i][0];
Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
Tm  = (*state)[i][0] ^ (*state)[i][1]; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp;
Tm  = (*state)[i][1] ^ (*state)[i][2]; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp;
Tm  = (*state)[i][2] ^ (*state)[i][3]; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp;
Tm  = (*state)[i][3] ^ t;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp;
```