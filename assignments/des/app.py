from flask import Flask, request
from pydes import *

app = Flask(__name__)

key = int(0).to_bytes(8)
d = des()

@app.post("/")
def oracle():
    pt = int(request.form["plaintext"], 2).to_bytes(8)
    ct = d.encrypt(key, pt)
    res = ''.join(f'{ord(c):08b}' for c in ct)
    return {
        "ciphertext": res 
    }