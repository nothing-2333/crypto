#include <string.h> 

#include "AES.h"

/*****************************************************************************/
/* 定义                                                       */
/*****************************************************************************/

// state 的列数。
#define Nb 4

// Nk 密钥长度，单位为 32 bit
// Nr 加密轮数。
#if defined(AES256) && (AES256 == 1)
    #define Nk 8
    #define Nr 14
#elif defined(AES192) && (AES192 == 1)
    #define Nk 6
    #define Nr 12
#else
    #define Nk 4   
    #define Nr 10    
#endif

/*****************************************************************************/
/* 变量                                                       */
/*****************************************************************************/

// state_t - 用于在解密过程中存储中间结果的数组。
typedef uint8_t state_t[4][4];

static const uint8_t sbox[256] = {
	// 0    1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 
};

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static const uint8_t rsbox[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d 
};
#endif

// 轮常量字数组 Rcon[i] 包含的值由 x 的 (i-1) 次幂给出，其中 x 是有限域 GF(2^8) 中的元素 {02} 的幂。
static const uint8_t Rcon[11] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 
};

/*****************************************************************************/
/* 函数                                                        */
/*****************************************************************************/

static uint8_t getSBoxValue(uint8_t num)
{
  	return sbox[num];
}

// 此函数生成 Nb(Nr+1) 个轮密钥。这些轮密钥在每一轮中用于解密状态。
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
	unsigned i, j, k;
	uint8_t tempa[4]; // 用于列/行操作
	
	// 第一个轮密钥就是密钥本身。
	for (i = 0; i < Nk; ++i)
	{
		RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
		RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
		RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
		RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
	}

	// 所有其他轮密钥都是从之前的轮密钥中生成的。
	for (i = Nk; i < Nb * (Nr + 1); ++i)
	{
		{
		k = (i - 1) * 4;
		tempa[0] = RoundKey[k + 0];
		tempa[1] = RoundKey[k + 1];
		tempa[2] = RoundKey[k + 2];
		tempa[3] = RoundKey[k + 3];
		}

		if (i % Nk == 0)
		{
		// 此函数将一个字中的 4 个字节向左循环移位一次。
		// [a0,a1,a2,a3] 变为 [a1,a2,a3,a0]

		// 函数 RotWord()
		{
			const uint8_t u8tmp = tempa[0];
			tempa[0] = tempa[1];
			tempa[1] = tempa[2];
			tempa[2] = tempa[3];
			tempa[3] = u8tmp;
		}

		// SubWord() 是一个函数，它接收一个四字节输入字，
		// 并对每个字节应用 S 盒，以产生一个输出字。

		// 函数 Subword()
		{
			tempa[0] = getSBoxValue(tempa[0]);
			tempa[1] = getSBoxValue(tempa[1]);
			tempa[2] = getSBoxValue(tempa[2]);
			tempa[3] = getSBoxValue(tempa[3]);
		}

		tempa[0] = tempa[0] ^ Rcon[i/Nk];
		}
	#if defined(AES256) && (AES256 == 1)
		if (i % Nk == 4)
		{
		// 函数 Subword()
		{
			tempa[0] = getSBoxValue(tempa[0]);
			tempa[1] = getSBoxValue(tempa[1]);
			tempa[2] = getSBoxValue(tempa[2]);
			tempa[3] = getSBoxValue(tempa[3]);
		}
		}
	#endif
		j = i * 4; k = (i - Nk) * 4;
		RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
		RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
		RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
		RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
	}
}

void AES_init_ctx(AES_ctx* ctx, const uint8_t* key)
{
  	KeyExpansion(ctx->RoundKey, key);
}
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
	KeyExpansion(ctx->RoundKey, key);
	memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
void AES_ctx_set_iv(AES_ctx* ctx, const uint8_t* iv)
{
  	memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
#endif

// 此函数通过 XOR 操作将轮密钥添加到 state 中。
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
		}
	}
}

// SubBytes 函数将 state 矩阵中的值替换为 S 盒中的值。
static void SubBytes(state_t* state)
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
		(*state)[j][i] = getSBoxValue((*state)[j][i]);
		}
	}
}

// ShiftRows() 函数将状态矩阵中的行向左循环移位。
// 每一行的移位偏移量不同。
// 偏移量 = 行号。因此，第一行不移位。
static void ShiftRows(state_t* state)
{
	uint8_t temp;

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
}

static uint8_t xtime(uint8_t x)
{
  	return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

// MixColumns 函数对 state 矩阵的列进行混合
static void MixColumns(state_t* state)
{
	uint8_t i;
	uint8_t Tmp, Tm, t;
	for (i = 0; i < 4; ++i)
	{  
		t   = (*state)[i][0];
		Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
		Tm  = (*state)[i][0] ^ (*state)[i][1]; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp;
		Tm  = (*state)[i][1] ^ (*state)[i][2]; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp;
		Tm  = (*state)[i][2] ^ (*state)[i][3]; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp;
		Tm  = (*state)[i][3] ^ t;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp;
	}
}

// Multiply 用于在有限域 GF(2^8) 中进行数字乘法。
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  	return (((y & 1) * x) ^
       ((y >> 1 & 1) * xtime(x)) ^
       ((y >> 2 & 1) * xtime(xtime(x))) ^
       ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x)))))); 
}

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

static uint8_t getSBoxInvert(uint8_t num)
{
  	return rsbox[num];
}

// InvMixColumns 是 MixColumns 的逆操作，用于解密过程。它通过有限域 GF(2^8) 中的乘法和异或操作，将状态矩阵的每一列进行逆向混合。
static void InvMixColumns(state_t* state)
{
	int i;
	uint8_t a, b, c, d;
	for (i = 0; i < 4; ++i)
	{ 
		a = (*state)[i][0];
		b = (*state)[i][1];
		c = (*state)[i][2];
		d = (*state)[i][3];

		(*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
		(*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
		(*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
		(*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
	}
}

// InvSubBytes 是 SubBytes 的逆操作，用于解密过程。它通过 S 盒的逆向替换值，将状态矩阵中的每个字节进行逆向替换。
static void InvSubBytes(state_t* state)
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
		(*state)[j][i] = getSBoxInvert((*state)[j][i]);
		}
	}
}

// InvShiftRows 是 ShiftRows 的逆操作，用于解密过程。它通过向右循环移位，将状态矩阵的每一行恢复到加密前的状态。
static void InvShiftRows(state_t* state)
{
	uint8_t temp;

	// 将第一行向右循环移位 1 列
	temp = (*state)[3][1];
	(*state)[3][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[0][1];
	(*state)[0][1] = temp;

	// 将第二行向右循环移位 2 列
	temp = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;

	temp = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;

	// 将第三行向右循环移位 3 列
	temp = (*state)[0][3];
	(*state)[0][3] = (*state)[1][3];
	(*state)[1][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[3][3];
	(*state)[3][3] = temp;
}
#endif

// 加密函数
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // 在开始轮操作之前，将第一轮密钥添加到状态中
  AddRoundKey(0, state, RoundKey);

  // 总共有 Nr 轮。
  // 前 Nr-1 轮是相同的。
  // 这些 Nr 轮在下面的循环中执行。
  // 最后一轮没有 MixColumns()
  for (round = 1; ; ++round)
  {
    SubBytes(state);
    ShiftRows(state);
    if (round == Nr) {
      break;
    }
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }
  // 在最后一轮添加轮密钥
  AddRoundKey(Nr, state, RoundKey);
}

// 解密函数
#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static void InvCipher(state_t* state, const uint8_t* RoundKey)
{
	uint8_t round = 0;

	// 在开始轮操作之前，将最后一轮密钥添加到状态中。
	AddRoundKey(Nr, state, RoundKey);

	// 总共有 Nr 轮。
	// 前 Nr-1 轮是相同的。
	// 这些 Nr 轮在下面的循环中执行。
	// 最后一轮没有 InvMixColumns()
	for (round = (Nr - 1); ; --round)
	{
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(round, state, RoundKey);
		if (round == 0) {
		break;
		}
		InvMixColumns(state);
	}
}
#endif

#if defined(ECB) && (ECB == 1)
void AES_ECB_encrypt_buffer(const AES_ctx* ctx, uint8_t* buf)
{
	Cipher((state_t*)buf, ctx->RoundKey);
}

void AES_ECB_decrypt_buffer(const AES_ctx* ctx, uint8_t* buf)
{
  	InvCipher((state_t*)buf, ctx->RoundKey);
}
#endif

#if defined(CBC) && (CBC == 1)

static void XorWithIv(uint8_t* buf, const uint8_t* Iv)
{
	uint8_t i;
	for (i = 0; i < AES_BLOCKLEN; ++i) // 无论密钥大小如何，块大小始终为 128 位。
	{
		buf[i] ^= Iv[i];
	}
}

void AES_CBC_encrypt_buffer(AES_ctx *ctx, uint8_t* buf, size_t length)
{
	size_t i;
	uint8_t *Iv = ctx->Iv;
	for (i = 0; i < length; i += AES_BLOCKLEN)
	{
		XorWithIv(buf, Iv);
		Cipher((state_t*)buf, ctx->RoundKey);
		Iv = buf;
		buf += AES_BLOCKLEN;
	}
	// 为下次调用储存 Iv
	memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}

void AES_CBC_decrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t length)
{
	size_t i;
	uint8_t storeNextIv[AES_BLOCKLEN];
	for (i = 0; i < length; i += AES_BLOCKLEN)
	{
		memcpy(storeNextIv, buf, AES_BLOCKLEN);
		InvCipher((state_t*)buf, ctx->RoundKey);
		XorWithIv(buf, ctx->Iv);
		memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
		buf += AES_BLOCKLEN;
	}
}

#endif

#if defined(CTR) && (CTR == 1)

// 对称操作：加密和解密使用相同的函数。注意：任何 IV/nonce 都不应与相同的密钥重复使用
void AES_CTR_xcrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t length)
{
	uint8_t buffer[AES_BLOCKLEN];
	
	size_t i;
	int bi;
	for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
	{
		if (bi == AES_BLOCKLEN) /* 我们需要重新生成 buffer 中的 XOR 补码 */
		{
		
		memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
		Cipher((state_t*)buffer, ctx->RoundKey);

		/* 增加 IV 并处理溢出 */
		for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
		{
		/* inc 将会溢出 */
			if (ctx->Iv[bi] == 255)
		{
			ctx->Iv[bi] = 0;
			continue;
			} 
			ctx->Iv[bi] += 1;
			break;   
		}
		bi = 0;
		}

		buf[i] = (buf[i] ^ buffer[bi]);
	}
}

#endif