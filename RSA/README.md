# RSA

## 整体梳理
mod 运算规定: a / b = c 余 d 则 a mod b = d。 RSA 加密: 明文^E mod N; RSA 解密: 密文^D mod N。公钥(E, N), 私钥(D, N), N 是公开的, 加密和解密的过程就是这么简单。生成密钥过程复杂一些，我用书中的例子展示
![alt text](图1.JPG)
![alt text](图2.JPG)