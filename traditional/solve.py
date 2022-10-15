
import string
import os
import itertools

# NOT WORKING DURING CTF

og = open("flag.enc.orig", "rb").read()[::1]
print(og)


new = open("flag.enc", "rb").read()[::1]


chars = string.ascii_letters + string.digits + string.punctuation


def compare(new):
    n = 0
    if new == og or len(new) > len(og):
        print("FOUND OUTPUT")
        print(new)
        exit()
    for i, c in enumerate(new):
        if c == og[i]:
            n += 1
    return n


flag = "c!}"


with open("flag.txt", "w") as f:
    f.write(flag)
os.system("./traditional.elf")
new = open("flag.enc", "rb").read()[::1]
print(new)

n = compare(new)

print("Starting n:", n)

while len(flag) < 34:
    start_n = n
    for i in itertools.combinations(chars, 3):
        tflag = "".join(i) + flag
        with open("flag.txt", "w") as f:
            f.write(tflag)
        os.system("./traditional.elf")
        new = open("flag.enc", "rb").read()[::1]
        x = compare(new)

        if x > n + 2:
            n = x
            print(new)
            print(tflag, n)
            flag = "".join(i) + flag
    if n == start_n:
        print("hit wall")
        exit(0)

# 7R#5er5ei3AB01}
