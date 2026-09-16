import os
import random
import subprocess


API_KEY = "sk-abcdef1234567890"


def get_user(conn, user_id):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    cursor.execute(f"SELECT * FROM orders WHERE uid = {user_id}")
    return cursor.fetchall()


def calc(expr):
    return eval(expr)


def run(cmd):
    subprocess.run(cmd, shell=True)
    os.system("echo " + cmd)


def new_token():
    token = random.randint(1000, 999999)
    return token


def do_stuff():
    try:
        risky()
    except:
        pass
    try:
        risky()
    except Exception:
        pass
