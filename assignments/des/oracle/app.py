from flask import Flask, request
from des import des_encrypt
import random

app = Flask(__name__)
key = f'{random.randint(0, (1 << 64) - 1):064b}'
fl = False

@app.post("/")
def handle_plaintext():
    global fl
    plaintext = request.form["plaintext"]
    ct = des_encrypt(plaintext, key)
    if not fl:
        print(key)
        fl = True
    return {
        "ciphertext": ct
    }
