#!/usr/bin/env python3

import string
import random

flag = "ASIS{ABCD}"


def distance(u, v):
    assert len(u) == len(v)
    d = 0
    for i in range(len(u)):
        if u[i] != v[i]:
            d += 1
    return d


def randstr(l):
    allstr, rstr = string.printable[:62] + '!?@-_{|}', ''
    for _ in range(l):
        rstr += allstr[random.randint(0, len(allstr) - 1)]
    return rstr


A = set(list(flag[5:-1]))
for x in range(1000):
    body = randstr(4)
    B = set(list(body))
    fake_flag = 'ASIS{' + f'{body}' + '}'
    print(f'{fake_flag}, d = {distance(flag, fake_flag)}, i = {len(A.intersection(B))}')
