from collections import defaultdict

# NOT WORKING DURING CTF


items = []

flag_len = 4


def intersect(s1, s2):
    res = ""
    for i in test_str1:
        if i in test_str2 and not i in res:
            res += i
    return res


with open("output_test.txt", "r") as f:
    lines = f.readlines()
    for l in lines:
        s = l.strip().split(",")
        pw = s[0]
        d = s[1].split("=")[1].strip()
        i = s[2].split("=")[1].strip()
        items.append((pw, d, i))


ibin = defaultdict(list)
dbin = defaultdict(list)

flag = [None] * flag_len

flag_chars = []

for i in items:
    dbin[i[1]].append(i[0])
    ibin[i[2]].append(i[0])


for i in dbin.keys():
    if i == flag:
        break
