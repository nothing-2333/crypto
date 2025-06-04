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