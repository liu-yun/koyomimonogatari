import json
from datetime import date, timedelta
from random import random
from math import floor
from Crypto.Cipher import AES

key = b'ghYY7sk0918<>s-3'
iv = b'93kJh*5&(sh20Cw?'
bs = 16


def decrypt(raw):
    unpad = lambda s: s[:-ord(s[len(s) - 1:])]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = unpad(cipher.decrypt(raw))
    print(dec)


def encrypt(raw):
    pad = lambda s: s + (bs - len(s) % bs) * chr(bs - len(s) % bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    enc = cipher.encrypt(pad(raw))
    print(enc)
    with open('cache.dat', 'wb') as f:
        f.write(enc)


def main():
    with open('cache.dat', 'rb') as f:
        cache = f.read()
    decrypt(cache)

    start_date = date(2016, 1, 1)
    delta = date.today() - start_date
    dates = [{'date': (start_date + timedelta(days=i)).strftime("%Y/%m/%d"),
              'x': floor(random() * 10 - 5),
              'y': floor(random() * 10 - 5)}
             for i in range(delta.days + 1)]
    encrypt(json.dumps(dates, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    main()