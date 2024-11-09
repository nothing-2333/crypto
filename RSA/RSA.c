#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define ACCRACY         5
#define SINGLE_MAX      10000
#define EXPONENT_MAX    1000
#define BUF_SIZE        1024

/**
 * 计算 a ^ b mod c
 */
int modpow(long long a, long long b, int c)
{
    int res = 1;
    while (b > 0)
    {
        if (b & 1)  // 使用长乘法，否则将溢出
        {
            res = (res * a) % c;
        }
        b = b >> 1;
        a = (a * a) % c;
    }

    return res;
}

/**
 * 计算 Jacobi 符号
 */
int jacobi(int a, int n)
{
    int twos, temp;
    int mult = 1;
    while (a > 1 && a != n)
    {
        a = a % n;
        if (a <= 1 || a == n) break;

        twos = 0;
        while (a % 2 == 0 && ++twos) a /= 2;
        if (twos > 0 && twos % 2 == 1) mult *= (n % 8 == 1 || n % 8 == 7) * 2 - 1;
        if (a <= 1 || a == n) break;
        if (n % 4 != 1 && a % 4 != 1) mult *= -1;
        temp = a;
        a = n;
        n = temp;
    }
    if (a == 0) return 0;
    else if (a == 1) return mult;
    else return 0;
}

/**
 * 检查 a 是否是 n 的欧拉见证
 */
int solovaPrime(int a, int n)
{
    int x = jacobi(a, n);
    if (x == -1) x = n - 1;
    return x != 0 && modpow(a, (n - 1) / 2, n) == x;
}

/**
 * 用 k 的精度检查 n 是否可能是素数
 */
int probablePrime(int n, int k)
{
    if (n == 2) return 1;
    else if (n % 2 == 0 || n == 1) return 0;
    while (k-- > 0)
    {
        if (!solovaPrime(rand() % (n - 2) + 2, n)) return 0;
    }
    
    return 1;
}

/**
 * 在 3 到 n - 1 选择一个随机素数
 */
int randPrime(int n)
{
    int prime = rand() % n;
    n += n % 2;
    prime += 1 - prime % 2;
    while (1)
    {
        if (probablePrime(prime, ACCRACY)) return prime;
        prime = (prime + 2) % n;
    }
}

/**
 * 求两个数的最大公约数
 */
int gcd(int a, int b)
{
    int temp;
    while (b != 0)
    {
        temp = b;
        b = a % b;
        a = temp;
    }
    
    return a;
}

/**
 * 在 3和 n - 1 之间找到随机指数 e，使得 e 与 phi 的最大公约数为 1
 */
int randExponent(int phi, int n)
{
    int e = rand() % n;
    while (1)
    {
        if (gcd(e, phi) == 1) return e;
        e = (e + 1) % n;
        if (e <= 2) e = 3;
    }
}

/**
 * 用扩展欧几里得法计算 n ^ -1 mod m
 */
int inverse(int n, int modulus)
{
    int a = n, b = modulus;
    int x = 0, y = 1, x0 = 1, y0 = 0, q, temp;

    while (b != 0)
    {
        q = a / b;
        temp = a % b;
        a = b;
        b = temp;

        temp = x;
        x = x0 - q * x;
        x0 = temp;

        temp = y;
        y = y0 - q * y;
        y0 = temp;
    }
    if (x0 < 0) x0 += modulus;
    

    return x0;
}

/**
 * 读取文件中要加密的文本，并做处理
 */
int readFile(FILE* fd, char** buffer, int bytes)
{
    int len = 0, cap = BUF_SIZE, r;
    char buf[BUF_SIZE];
    *buffer = (char*)malloc(BUF_SIZE * sizeof(char));
    while ((r = fread(buf, sizeof(char), BUF_SIZE, fd)) > 0)
    {
        if (len + r >= cap)
        {
            cap *= 2;
            *buffer = (char*)realloc(*buffer, cap);
        }
        memcpy(&(*buffer)[len], buf, r);
        len += r;
    }

    if (len + bytes - len % bytes > cap) *buffer = (char*)realloc(*buffer, len + bytes - len % bytes);
    do
    {
        (*buffer)[len] = '\0';
        len++;
    } while (len % bytes != 0);

    return len;
}

/**
 * 使用公钥指数 e 和模量 n 对消息 m 进行编码
 */
int encode(int m , int e, int n)
{
    return modpow(m, e, n);
}

/**
 * 使用私钥指数 d 和模量 n 对密文 c 进行解码
 */
int decode(int c, int d, int n)
{
    return modpow(c, d, n);
}

/**
 * 使用公钥（指数、模数)对给定长度的消息进行编码
 */
int* encodeMessage(int len, int bytes, char* message, int exponent, int modulus)
{
    int* encoded = (int*)malloc((len / bytes) * sizeof(int));
    int x, i, j;
    for (i = 0; i < len; i += bytes)
    {
        x = 0;
        for (j = 0; j < bytes; j++)
        {
            x += message[i + j] * (1 << (7 * j));
        }

        encoded[i / bytes] = encode(x, exponent, modulus);
        printf("%d ", encoded[i / bytes]);
    }
    return encoded;
}

/**
 * 使用私钥（指数、模数)解码给定长度的密码
 */
int* decodeMessage(int len, int bytes, int* cryptogram, int exponent, int modulus)
{
    int* decoded = (int*)malloc(len * bytes * sizeof(int));
    int x, i, j;
    for (i = 0; i < len; ++i)
    {
        x = decode(cryptogram[i], exponent, modulus);
        for (j = 0; j < bytes; ++j)
        {
            decoded[i * bytes + j] = (x >> (7 * j)) % 128;
            if (decoded[i * bytes + j] != '\0') printf("%c", decoded[i * bytes + j]);
        }
    }

    return decoded;
}

int main(void)
{
    int p, q, n, phi, e, d, bytes, len;
    int* encoded;
    int* decoded;
    char* buffer;
    FILE* f;
    srand(time(NULL));

    while (1)
    {
        p = randPrime(SINGLE_MAX);
        q = randPrime(SINGLE_MAX);
        n = p * q;
        if (n >= 128) break;
    }

    if (n >> 21) bytes = 3;
    else if (n >> 14) bytes = 2;
    else bytes = 1;

    phi = (p - 1) * (q - 1);
    
    e = randExponent(phi, EXPONENT_MAX);
    d = inverse(e, phi);

    f = fopen("RSA/data.txt", "r");
    if (f == NULL) return EXIT_FAILURE;

    len = readFile(f, &buffer, bytes);
    fclose(f);

    encoded = encodeMessage(len, bytes, buffer, e, n);
    decoded = decodeMessage(len / bytes, bytes, encoded, d, n);

    free(encoded);
    free(decoded);
    // free(buffer);

    return EXIT_SUCCESS;
}