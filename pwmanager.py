import getpass
import sqlite3
from pathlib import Path

import pyperclip
from cryptography.fernet import Fernet
import hashlib
import base64


def genkey(key):
    hashedKey = hashlib.sha256(key.encode()).digest()
    kodKey = base64.urlsafe_b64encode(hashedKey)

    while len(kodKey) < 32:
        kodKey += b'='
    return kodKey


def encrypt(key, path):
    fernet = Fernet(key)
    with open(path, "rb") as f:
        fb = f.read()
    encrptbytes = fernet.encrypt(fb)
    with open(path, "wb") as f:
        f.write(encrptbytes)


def decrypt(key, path):
    fernet = Fernet(key)
    with open(path, "rb") as f:
        fb = f.read()
    encrptbytes = fernet.decrypt(fb)
    with open(path, "wb") as f:
        f.write(encrptbytes)


def load_data_from_db(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM pw")
    rows = cursor.fetchall()

    conn.close()

    data = [{'id': row[0], 'value': row[1]} for row in rows]
    return data


def save_data_to_db(db_path, data):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM pw")

    for row in data:
        cursor.execute("INSERT INTO pw VALUES (?, ?)",
                       (row['id'], row['value']))

    conn.commit()
    conn.close()

def get(data, id):
    for item in data:
        if item['id'] == id:
            return item['value']
    return None

def remove_by_id(data, id_to_remove):
    data[:] = [item for item in data if item['id'] != id_to_remove]

if __name__ == "__main__":
    path = Path("exend.db")

    if not path.is_file():
        while True:
            pw = getpass.getpass("Please create a password: ")
            pw2 = getpass.getpass("Repeat password: ")

            if pw == pw2:
                print("Password set successfully.")
                break
            else:
                print("Passwords do not match. Please try again.")

        key = genkey(pw)
        path.touch()
        c = sqlite3.connect("exend.db")
        cs = c.cursor()
        cs.execute("CREATE TABLE IF NOT EXISTS pw(id TEXT, value TEXT)")
        cs.execute("INSERT INTO pw VALUES ('google', 'cocplayer')")
        c.commit()
        c.close()
        encrypt(key, "exend.db")
    else:
        pw = getpass.getpass("Enter your password: ")
        key = genkey(pw)
        try:
            decrypt(key, "exend.db")

            data = load_data_from_db("exend.db")
            # print(data)
            # data.append({'id': 'minecraft', 'value': 'ichmagbäume'})
            # save_data_to_db("exend.db", data)
            encrypt(key, "exend.db")

            print("1 : copy Service password\n"
                  "2 : create Service\n"
                  "3 : edit Service\n"
                  "4 : delete Service\n"
                  "5 : Quit")
            while True:
                i = input()
                if i == "1":
                    ip = input("Service: ")
                    pw = get(data, ip)
                    if pw is None:
                        print("Service not found")
                    else:
                        pyperclip.copy(pw)
                        print("copied")
                elif i == "2":
                    print("spaces will be deleted.")
                    ip = input("Service name: ").replace(" ", "")
                    if ip == "":
                        print("empty str!")
                    else:
                        pw = getpass.getpass("Password: ").replace(" ", "")
                        if pw == "":
                            print("empty str!")
                        else:
                            data.append({'id': ip, 'value': pw})
                            print("Service created")
                elif i == "3":
                    print("spaces will be deleted.")
                    ip = input("Service name: ").replace(" ", "")
                    if ip == "" or get(data, ip) is None:
                        print("Service not found!")
                    else:
                        pw = getpass.getpass("New password: ").replace(" ", "")
                        if pw == "":
                            print("empty str!")
                        else:
                            remove_by_id(data, ip)
                            data.append({'id': ip, 'value': pw})
                            print("Service edited")
                elif i == "5":
                    break

            decrypt(key, "exend.db")
            save_data_to_db("exend.db", data)
            encrypt(key, "exend.db")

        except Exception as e:
            print("Failed to decrypt the database. Check your password.")
            print(e)
