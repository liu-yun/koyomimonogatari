def decode(s, p):
    i = 0
    j = len(s)
    while i != j:
        k = ord(s[i]) ^ p & 0x5F
        p += 1
        m = i + 1
        s = s[:i] + chr(k) + s[i + 1:]
        i = m
    return s[:j]


def main():
    a = decode("agsm", 1701)
    print(a)


if __name__ == '__main__':
    main()
