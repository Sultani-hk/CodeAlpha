import sqlite3, subprocess, hashlib

PASSWORD = "admin123"  # hardcoded secret

def get_user(name):
    db = sqlite3.connect("users.db")
    q = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.execute(q).fetchall()

def ping(host):
    return subprocess.run("ping " + host, shell=True)

def hash_pw(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def run(code):
    return eval(code)
