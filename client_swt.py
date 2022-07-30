#TCP Client
from Crypto.Cipher import AES
from re import U

import encodings
import hashlib
import json
import random
import socket
import struct
import sys
import time

## SOCKET CLIENT CONFIG
TCP_IP = '127.0.0.1'
TCP_PORT = 5003
BUFFER_SIZE = 1024

## AES
CIPHER_KEY=b'bQeThWmZq4t7w!z%C*F-JaNdRfUjXn2r' #Shared Encryption/decryption Key
NONCE=b'dRgUkXp2s5v8y/B?E(G+KbPeShVmYq3t' #shared NONCE key for validity

## ZKP Element  
G = [101, 103, 107, 109, 113, 127, 
    131, 137, 139, 149, 151, 157, 
    163, 167, 173, 179, 181, 191, 
    193, 197, 199]

PRIME = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

## FROM THIS LINE
## FUNCTION READ & WRITE
def readFile(filename):
    try:
        full_bytes = b''
        with open(filename, "rb") as f:
            while True:
                # read the bytes from the file
                bytes_read = f.read(BUFFER_SIZE)
                if not bytes_read:
                    # file transmitting is done
                    break
                full_bytes += bytes_read
        return full_bytes
    except FileNotFoundError:
        print("File tidak diketemukan")
    

def readUsers():
    try:
        with open("users.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def writeUsers(usr):
    with open("users.json", "w+") as f:
            json.dump(usr, f)

## FROM THIS LINE
## FUNCTION SOCKET COMM
def recvMessage(conn_server):
    size = struct.unpack("i", conn_server.recv(struct.calcsize("i")))[0]
    full_msg = b""
    while len(full_msg) < size:
        msg = conn_server.recv(size - len(full_msg))
        if not msg:
            return None
        full_msg += msg
    return full_msg

def sendMessage(conn_server , bytes_data):
    conn_server.send(struct.pack("i", len(bytes_data)) + bytes_data)

## FROM THIS LINE 
## FUNCTION ZKP AUTH
def __YvalZKP(_g, password, N):
    ## Fungsi mengembalikan 
    ## nilai zkp x dan y
    _x = int(hashlib.sha256(password.encode('utf-8')).hexdigest(), 16) % 10**2
    _Y = pow(_g,_x) % N
    return _Y,_x

def __proverZKP(user_pass, _g0, _a, _N):
    ## Fungsi mengembalikan 
    ## nilai zkp c dan zx
    infozkp = []
    for i in range(len(user_pass)):
        _Y,_x = __YvalZKP(_g0, user_pass[i], _N)
        _rx = random.randint(20000, 25000)
        _T1 = pow(_g0,_rx) % _N
        _val_c = str(_Y) + str(_T1) + _a[i]
        _c = hashlib.sha256(_val_c.encode('utf-8')).hexdigest()
        _Zx = _rx - ((int(_c,16) % 10**2)* _x)
        infozkp.append([_c, _Zx])

    return infozkp

def input_pass(n):
    ## Fungsi melakukan looping password user
    ## user akan memasukan looping sebanyak n kali
    pass_arr_login = []
    for i in range(1,n+1):
        pass_inpt = input(f"Masukan password anda ({i}/{n}): ")
        pass_arr_login.append(pass_inpt)
    return pass_arr_login

def registerUser(sock_server):
    ## Fungsi mendaftarkan username client
    ## jika username sudah terdaftar di server namun tidak di lokal
    ## username tidak bisa didaftarkan
    print("## Menu Registrasi ##")
    print("Masukan Username")
    username = input()
    sendMessage(sock_server, bytes(username, "utf-8"))
    reply = recvMessage(sock_server).decode("utf-8")
    if reply == '0':
        print("Masukan Password")
        password = input()
        _g = random.choice(G)
        _N = random.choice(PRIME)
        _Y,_x = __YvalZKP(_g, password, _N)
        auth_data = json.dumps({'g':_g, 'y':_Y, 'n':_N})
        sendMessage(sock_server, bytes(auth_data, "utf-8"))

        user = {username:{'g':_g, 'n':_N}}
        writeUsers(user)
        print(f"Username {username} telah terdaftar..")
    else:
        print(f"Username {username} sudah terdaftar ..")

def loginUser(sock_server):
    token = json.loads(recvMessage(sock_server).decode("utf-8").strip())

    print("## Menu Registrasi ##")
    print("Masukan Username")
    username = input()
    list_user = readUsers()
    if username in list_user.keys():
        print("Masukan Password")
        password_list = input_pass(5)
        print("Masukan Nama File")
        filename = input()
        file_bytes = readFile(filename)
        CIPHER = AES.new(CIPHER_KEY, AES.MODE_EAX, NONCE)
        ciphertext, tag = CIPHER.encrypt_and_digest(file_bytes)
        auth_info = __proverZKP(password_list, list_user[username]["g"], token, list_user[username]["n"])
        auth_data = json.dumps({
            'username':username,
            'auth':auth_info,
            'fname': filename
        })

        sendMessage(sock_server, bytes(auth_data, "utf-8"))
        sendMessage(sock_server, ciphertext)
    else:
        print("Username tidak terdaftar")   


## FROM THIS LINE 
## MAIN PROGRAM
def main():
    s.connect((TCP_IP, TCP_PORT))
    input_choice = -1
    while 1:
        print("## Pilih Fungsi ##")
        print("1.Registrasi ")
        print("2.Send Data ")
        print("3.Keluar")
        print("Ketik pilihan anda ... ")
        input_choice = int(input())
        if input_choice == 1:
            sendMessage(s,bytes('1',"utf-8"))
            registerUser(s)
        elif input_choice == 2:
            sendMessage(s,bytes('2',"utf-8"))
            loginUser(s)
        elif input_choice == 3:
            sendMessage(s,bytes('3',"utf-8"))
            break
    s.close()

if __name__ == "__main__":
    main()