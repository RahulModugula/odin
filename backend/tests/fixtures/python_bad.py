import os
import sys
import json
import subprocess

x = 10
y = "hello"
password = "admin123"
api_key = "sk-1234567890abcdef"

def f(a,b,c,d,e,f,g):
    result = []
    for i in range(len(a)):
        if a[i] > 0:
            if b[i] > 0:
                if c[i] > 0:
                    if d[i] > 0:
                        for j in range(len(e)):
                            if e[j] == f[i]:
                                try:
                                    val = a[i] * b[i] + c[i] / d[i]
                                    result.append(val)
                                except:
                                    pass
    return result

def run_cmd(user_input):
    os.system("echo " + user_input)
    subprocess.call(user_input, shell=True)
    eval(user_input)

def get_data(id):
    query = "SELECT * FROM users WHERE id = " + str(id)
    return query

class thing:
    def __init__(self, a, b, c, d, e):
        self.a = a
        self.b = b
        self.c = c
        self.d = d
        self.e = e

    def do_stuff(self):
        if self.a:
            if self.b:
                if self.c:
                    return self.d + self.e
        return None
