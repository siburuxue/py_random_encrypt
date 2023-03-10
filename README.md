# random_encrypt

## 基于openssl加密
### 仅使用了 AES-128-CBC
#### 根据时间戳所在的时间区间，时区信息计算加密的key，iv
#### 为每个key设置有效时间(默认5秒，冗余2秒)，在不同的时间区间（左包右闭），相同文本加密后的字符串不同
#### 默认时区为东八区，加密端和解密端通过统一时区对齐时间，避免不同时区，同时间段，加密后的密文不同，导致无法解密
#### 在使用时，必须自定义盐值，不能为空。
```python
if self._salt == "":
    raise Exception('the salt can not be empty.')
```
#### Encrypt函数返回 (加密后字符串,key,iv,加密时使用的时间戳) 供解密失败后备查。

## Install
```shell
pip3 install random_tool
```

示例代码：
```python
from random_tool.random_encrypt import RandomEncrypt

if __name__ == '__main__':
    e = RandomEncrypt({"salt": "salt"})
    s = e.encrypt("hello world")
    print(s)
    t = e.decrypt(s[0])
    print(t)
```