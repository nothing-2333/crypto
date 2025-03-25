# c/c++ 实现一些标准加密
c/c++ 实现一些标准加密，并且为每个加密做一个 README ，其中记录其主要流程和特点，方便更好的识别

## 每个加密配上流程笔记，以应对魔改的算法。

### 算法统计
MD5

RC4

TEA

XTEA

XXTEA

AES

base64

RSA

SHA256

SM2

SM3

SM4

HMAC 只给出 py 实例，就是在`hash算法`的基础上用 key 加了两层扰动，不在专门实现、说明。
```py
import hashlib
import binascii

def hmac_sha256(key, message):
    # 将密钥和消息转换为字节
    key_bytes = key.encode('utf-8')
    message_bytes = message.encode('utf-8')

    # 如果密钥长度小于64字节，用0x00填充到64字节
    if len(key_bytes) < 64:
        key_bytes = key_bytes.ljust(64, b'\x00')
    # 如果密钥长度大于64字节，先用SHA-256压缩
    elif len(key_bytes) > 64:
        key_bytes = hashlib.sha256(key_bytes).digest()

    # 内部和外部填充
    inner_pad = b'\x36' * 64  # 内部填充
    outer_pad = b'\x5c' * 64  # 外部填充

    # 计算内部哈希
    inner_key = bytes([key_bytes[i] ^ inner_pad[i] for i in range(64)])
    inner_hash = hashlib.sha256(inner_key + message_bytes).digest()

    # 计算外部哈希
    outer_key = bytes([key_bytes[i] ^ outer_pad[i] for i in range(64)])
    hmac_result = hashlib.sha256(outer_key + inner_hash).digest()

    # 返回十六进制表示的HMAC值
    return binascii.hexlify(hmac_result).decode('utf-8')

# 测试代码
key = "my_secret_key"
message = "Hello, HMAC!"
hmac_value = hmac_sha256(key, message)
print(f"HMAC-SHA256: {hmac_value}")
```

### 参考链接
https://blog.csdn.net/OrientalGlass/article/details/129400866

https://blog.csdn.net/qq_54223524/article/details/135889348

https://blog.csdn.net/weixin_45031801/article/details/126728082

https://www.cnblogs.com/myth67/p/13247074.html

https://blog.csdn.net/xiao__1bai/article/details/123307059

https://blog.csdn.net/qq_28205153/article/details/55798628

https://github.com/kokke/tiny-AES-c/tree/master

https://blog.csdn.net/m0_51913750/article/details/128426561

https://github.com/talent518/md5/blob/master/main.c

https://github.com/NEWPLAN/SMx

https://blog.csdn.net/m0_46577050/article/details/142916092

https://github.com/terrantsh/RSA2048

https://github.com/ikantech/gm

https://github.com/Aries-orz/nano-sm2/blob/master/sm2.h

https://github.com/jestan/easy-ecc/blob/master/ecc.c

https://zhuanlan.zhihu.com/p/336054453