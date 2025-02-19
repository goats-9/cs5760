from flask import Flask, request
from pydes import *
import random

app = Flask(__name__)

key = b"0000000a"
d = des()

@app.post("/")
def oracle():
    pt = int(request.form["plaintext"], 2).to_bytes(8)
    ct = d.encrypt(key, pt)
    res = 0
    for c in ct:
        res = (res << 8) + ord(c)
    res = f'{res:064b}'
    return {
        "ciphertext": res
    }