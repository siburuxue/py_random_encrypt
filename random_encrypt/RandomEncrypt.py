import hashlib
import math
import time
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


class RandomEncrypt:
    # 北京时间时区信息
    _timezoneOffset = 8

    # key有效期（单位秒）
    _timeInterval = 5

    # 加密key长度
    _keyLength = 16

    # 如果跨区间 冗余几秒
    _secondRedundancy = 2

    # 当前时区（北京/东八区）时间戳
    _timestamp = 0

    # 自定义盐值
    _salt = ""

    _map = {
        "1": '#',
        "2": '0',
        "3": '*',
        "4": '9',
        "5": '8',
        "6": '7',
        "7": '6',
        "8": '5',
        "9": '4',
        "*": '3',
        "0": '2',
        "#": '1',
    }

    _cipherAlgoMap = (
        "AES-128-CBC",
        "ARIA-128-CTR",
        "CAMELLIA-128-CBC",
        "SEED-CBC",
        "SM4-CBC",
        "AES-128-CBC-HMAC-SHA256",
    )

    def __init__(self, config):
        if 'salt' in config:
            self._salt = config['salt']
        if 'offset' in config:
            self._timezoneOffset = config['offset']
        if 'timeInterval' in config:
            self._timeInterval = config['timeInterval']
        if 'secondRedundancy' in config:
            self._secondRedundancy = config['secondRedundancy']

    def encrypt(self, data):
        (key, iv) = self._key()
        # AES-128-CBC
        key_bytes = key.encode()
        iv_bytes = iv.encode()
        msg = pad(data.encode(), AES.block_size)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        cipher_text = cipher.encrypt(msg)
        return b64encode(cipher_text).decode('utf-8'), key, iv, self._timestamp

    def decrypt(self, data):
        timestamp = self._get_timestamp()
        s = self.do_decrypt(data, timestamp)
        if s == "" and self._is_re_decrypted(timestamp):
            s = self.do_decrypt(data, timestamp - self._timeInterval)
        return s

    def do_decrypt(self, data, timestamp):
        (key, iv) = self._key(timestamp)
        # AES-128-CBC
        decipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
        return unpad(decipher.decrypt(b64decode(data)), AES.block_size).decode('utf-8')

    def decrypt_by_key_iv(self, data, key, iv):
        # AES-128-CBC
        decipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
        return unpad(decipher.decrypt(b64decode(data)), AES.block_size).decode('utf-8')

    def _is_re_decrypted(self, timestamp):
        return timestamp % self._timeInterval <= self._secondRedundancy

    def _get_cipher_algo(self):
        return self._cipherAlgoMap[0]

    def _key(self, timestamp=0):
        if timestamp == 0:
            timestamp = self._get_timestamp()
        self._timestamp = timestamp
        timestamp = self._get_time_group(timestamp)
        datetime = self._format_datetime(timestamp)
        key = "".join(list(map(lambda x: self._map[x], list(datetime))))
        index = int(datetime) % self._keyLength
        passphrase = datetime + key + datetime
        iv = key + datetime + key
        return self._get_encrypt_key(passphrase, index), self._get_encrypt_key(iv, index)

    def _get_timestamp(self):
        return math.ceil(time.time())

    def _get_time_group(self, timestamp):
        return int(math.ceil(timestamp / self._timeInterval)) * self._timeInterval

    def _format_datetime(self, timestamp):
        offset = int(0 - time.timezone / 3600)
        timestamp += (self._timezoneOffset - offset) * 3600
        return time.strftime('%Y%m%d%H%M%S', time.localtime(timestamp))

    def _get_encrypt_key(self, key, index):
        if self._salt == "":
            raise Exception('the salt can not be empty.')
        md5 = hashlib.md5()
        md5.update((key + self._salt).encode('utf-8'))
        return md5.hexdigest().lower()[index: index + self._keyLength]
