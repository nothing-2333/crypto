#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
 
#define ACCURACY 5
#define SINGLE_MAX 10000
#define EXPONENT_MAX 1000
#define BUF_SIZE 1024
 
/**
 * Computes a^b mod c，计算a^b mod c
 */
int modpow(long long a, long long b, int c) {
    int res = 1;
    while(b > 0) {
        /* Need long multiplication else this will overflow...
         必须使用长乘法，否则这将溢出*/
        if(b & 1) {
            res = (res * a) % c;
        }
        b = b >> 1;
        a = (a * a) % c; /* Same deal here */
    }
    return res;
}
 
/**
 * Computes the Jacobi symbol, (a, n)，计算Jacobi符号（a,n）
 */
int jacobi(int a, int n) {
    int twos, temp;
    int mult = 1;
    while(a > 1 && a != n) {
        a = a % n;
        if(a <= 1 || a == n) break;
        twos = 0;
        while(a % 2 == 0 && ++twos) a /= 2; /* Factor out multiples of 2 ,减去2的倍数*/
        if(twos > 0 && twos % 2 == 1) mult *= (n % 8 == 1 || n % 8 == 7) * 2 - 1;
        if(a <= 1 || a == n) break;
        if(n % 4 != 1 && a % 4 != 1) mult *= -1; /* Coefficient for flipping，翻转系数 */
        temp = a;
        a = n;
        n = temp;
    }
    if(a == 0) return 0;
    else if(a == 1) return mult;
    else return 0; /* a == n => gcd(a, n) != 1 */
}
 
/**
 * Check whether a is a Euler witness for n，检查a是否为n的欧拉见证 */
int solovayPrime(int a, int n) {
    int x = jacobi(a, n);
    if(x == -1) x = n - 1;
    return x != 0 && modpow(a, (n - 1)/2, n) == x;
}
 
/**
 * Test if n is probably prime, using accuracy of k (k solovay tests)，用k的精度检查n是否可能是素数 */
int probablePrime(int n, int k) {
    if(n == 2) return 1;
    else if(n % 2 == 0 || n == 1) return 0;
    while(k-- > 0) {
        if(!solovayPrime(rand() % (n - 2) + 2, n)) return 0;
    }
    return 1;
}
 
/**
 * Find a random (probable) prime between 3 and n - 1在3和（n-1）之间找一个随机素数, this distribution is，
 * nowhere near uniform, see prime gaps
 */
int randPrime(int n) {
    int prime = rand() % n;
    n += n % 2; /* n needs to be even so modulo wrapping preserves oddness */
    prime += 1 - prime % 2;
    while(1) {
        if(probablePrime(prime, ACCURACY)) return prime;
        prime = (prime + 2) % n;
    }
}
 
/**
 * Compute gcd(a, b)，计算gcd（a,b）
 */
int gcd(int a, int b) {
    int temp;
    while(b != 0) {
        temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}
 
/**
 * Find a random exponent x between 3 and n - 1 such that gcd(x, phi) = 1,在3和n-1之间找到随机指数x，使得gcd(x,phi)=1
 * this distribution is similarly nowhere near uniform,这种分布同样不接近制服
 */
int randExponent(int phi, int n) {
    int e = rand() % n;
    while(1) {
        if(gcd(e, phi) == 1) return e;
        e = (e + 1) % n;
        if(e <= 2) e = 3;
    }
}
 
/**
 * Compute n^-1 mod m by extended euclidian method，用扩展欧几里得法计算n^-1 mod m
 */
int inverse(int n, int modulus) {
    int a = n, b = modulus;
    int x = 0, y = 1, x0 = 1, y0 = 0, q, temp;
    while(b != 0) {
        q = a / b;
        temp = a % b;
        a = b;
        b = temp;
        temp = x; x = x0 - q * x; x0 = temp;
        temp = y; y = y0 - q * y; y0 = temp;
    }
    if(x0 < 0) x0 += modulus;
    return x0;
}
 
/**
 * Read the file fd into an array of bytes ready for encryption.将文件fd读入准备加密的字节数组
 * The array will be padded with zeros until it divides the number of数组将填充零，知道它划分每个块加密的字节数
 * bytes encrypted per block. Returns the number of bytes read.返回读取的字节数
 */
int readFile(FILE* fd, char** buffer, int bytes) {
    int len = 0, cap = BUF_SIZE, r;
    char buf[BUF_SIZE];
    *buffer = (char *)malloc(BUF_SIZE * sizeof(char));
    while((r = fread(buf, sizeof(char), BUF_SIZE, fd)) > 0) {
        if(len + r >= cap) {
            cap *= 2;
            *buffer = (char *)realloc(*buffer, cap);
        }
        memcpy(&(*buffer)[len], buf, r);
        len += r;
    }
    /* Pad the last block with zeros to signal end of cryptogram. An additional block is added if there is no room，将最后一个带有零的块插入密码的信号端。 如果没有房间，则增加一个额外的街区 */
    if(len + bytes - len % bytes > cap) *buffer = (char *)realloc(*buffer, len + bytes - len % bytes);
    do {
        (*buffer)[len] = '\0';
        len++;
    }
    while(len % bytes != 0);
    return len;
}
 
/**
 * Encode the message m using public exponent and modulus, c = m^e mod n使用公共指数和模量对消息m进行编码，c = m^e Mod n
 */
int encode(int m, int e, int n) {
    return modpow(m, e, n);
}
 
/**
 * Decode cryptogram c using private exponent and public modulus, m = c^d mod n，用私有指数和公共模量解码密码c，m = c^d Mod n
 */
int decode(int c, int d, int n) {
    return modpow(c, d, n);
}
 
/**
 * Encode the message of given length, using the public key (exponent, modulus)
 * The resulting array will be of size len/bytes, each index being the encryption
 * of "bytes" consecutive characters, given by m = (m1 + m2*128 + m3*128^2 + ..),
 * encoded = m^exponent mod modulus
 * 使用公钥（指数、模数)对给定长度的消息进行编码）
 得到的数组将是大小为len/字节，每个索引是由m=(m1m2*128m3*128^2.)给出的“字节”连续字符的加密，编码=m^指数mod模量
 */
int* encodeMessage(int len, int bytes, char* message, int exponent, int modulus) {
    int *encoded = (int *)malloc((len/bytes) * sizeof(int));
    int x, i, j;
    for(i = 0; i < len; i += bytes) {
        x = 0;
        for(j = 0; j < bytes; j++) x += message[i + j] * (1 << (7 * j));
        encoded[i/bytes] = encode(x, exponent, modulus);
        printf("%d ", encoded[i/bytes]);
    }
    return encoded;
}
 
/**
 * Decode the cryptogram of given length, using the private key (exponent, modulus)
 * Each encrypted packet should represent "bytes" characters as per encodeMessage.
 * The returned message will be of size len * bytes.
 * 使用私钥（指数、模数)解码给定长度的密码）
 每个加密的数据包应该按照编码消息表示“字节”字符。
 返回的消息大小为len*字节。
 */
int* decodeMessage(int len, int bytes, int* cryptogram, int exponent, int modulus) {
    int *decoded = (int *)malloc(len * bytes * sizeof(int));
    int x, i, j;
    for(i = 0; i < len; i++) {
        x = decode(cryptogram[i], exponent, modulus);
        for(j = 0; j < bytes; j++) {
            decoded[i*bytes + j] = (x >> (7 * j)) % 128;
            if(decoded[i*bytes + j] != '\0') printf("%c", decoded[i*bytes + j]);
        }
    }
    return decoded;
}
 
/**
 * Main method to demostrate the system. Sets up primes p, q, and proceeds to encode and
 * decode the message given in "text.txt"
 * 系统降级的主要方法。 设置素数p，q，并开始编码和
 *解码“text.txt”中给出的消息；
 */
int main(void) {
    int p, q, n, phi, e, d, bytes, len;
    int *encoded, *decoded;
    char *buffer;
    FILE *f;
    srand(time(NULL));
    while (1) 
    {
        p = randPrime(SINGLE_MAX);
        printf("生成第一个随机素数, p = %d ... ", p);
        getchar();
 
        q = randPrime(SINGLE_MAX);
        printf("生成第二个随机素数, q = %d ... ", q);
        getchar();
 
        n = p * q;
        printf("计算p和q的乘积n, n = pq = %d ... ", n);
        if (n < 128) 
        {
            printf("Modulus is less than 128, cannot encode single bytes. Trying again ... ");
            getchar();
        }
        else break;
    }
    if(n >> 21) bytes = 3;
    else if(n >> 14) bytes = 2;
    else bytes = 1;
    getchar();
 
    phi = (p - 1) * (q - 1);
    printf("计算欧拉函数的值phi, phi = %d ... ", phi);
    getchar();
 
    e = randExponent(phi, EXPONENT_MAX);
    printf("选取一个随机素数e, e = %d...\n获得公钥 (%d, %d) ... ", e, e, n);
    getchar();
 
    d = inverse(e, phi);
    printf("计算模反元素d, d = %d...\n获得密钥 (%d, %d) ... ", d, d, n);
    getchar();
 
    printf("打开文件 \"data.txt\" 用于读取信息\n");
    f = fopen("data.txt", "r");
    if(f == NULL) {
        printf("Failed to open file \"data.txt\". Does it exist?\n");
        return EXIT_FAILURE;
    }
    len = readFile(f, &buffer, bytes); /* len will be a multiple of bytes, to send whole chunks伦将是多个字节，以发送整个块 */
    fclose(f);
 
    printf("文件 \"data.txt\" 读取成功, 读取到%d字节. 以%d字节的字节流编码 ... ", len, bytes);
    getchar();
    printf("加密得密文为：");
    encoded = encodeMessage(len, bytes, buffer, e, n);
    printf("\n编码成功完成 ... ");
    getchar();
 
 
    printf("正在解码编码的信息 ... ");
    getchar();
    printf("解码得明文为：");
    decoded = decodeMessage(len/bytes, bytes, encoded, d, n);
 
 
    printf("\nRSA算法演示完成!\n");
 
    free(encoded);
    free(decoded);
    free(buffer);
    return EXIT_SUCCESS;
}