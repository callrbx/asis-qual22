

e = open("flag.enc", "rb").read()

t = e[13:-13]

for x in t:
    print(hex(x), end=" ")

print()
