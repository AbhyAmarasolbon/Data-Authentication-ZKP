#TCP Server
from base64 import decode
from Crypto.Cipher import AES
from unicodedata import decimal

import hashlib
import json
import os
import secrets
import socket
import struct
import sys
import time
import _thread

## SOCKET SERVER CONFIG
TCP_IP = '127.0.0.1'
TCP_PORT = 5003
BUFFER_SIZE = 1024

## AES
CIPHER_KEY=b'bQeThWmZq4t7w!z%C*F-JaNdRfUjXn2r' #Shared Encryption/decryption Key
NONCE=b'dRgUkXp2s5v8y/B?E(G+KbPeShVmYq3t' #shared NONCE key for validity

## FROM THIS LINE
## FUNCTION READ & WRITE
def writeFile(filename, full_message):
    filename = os.path.basename(filename)
    with open(f"dest/{filename}", "wb") as f:
        f.write(full_message)

def readClient():
    try:
        with open("client.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def writeClient(usr):
    with open("client.json", "w+") as f:
            json.dump(usr, f)

## FROM THIS LINE
## FUNCTION SOCKET COMM
def recvMessage(conn_client):
    size = struct.unpack("i", conn_client.recv(struct.calcsize("i")))[0]
    full_msg = b""
    while len(full_msg) < size:
        msg = conn_client.recv(size - len(full_msg))
        if not msg:
            return None
        full_msg += msg
    return full_msg

def sendMessage(conn_client , bytes_data):
    conn_client.sendall(struct.pack("i", len(bytes_data)) + bytes_data)

## FROM THIS LINE 
## FUNCTION ZKP AUTH
def __YvalZKP(_g, password, N):
    ## Fungsi mengembalikan 
    ## nilai zkp x dan y
    _x = int(hashlib.sha256(password.encode('utf-8')).hexdigest(), 16) % 10**2
    _Y = pow(_g,_x) % N
    return _Y,_x

def __verifierZKP(c_client, Zx_client, _g0, _Y, _N, token):
    c_server = []
    for i in range(len(c_client)):
        _Ts = ((pow(_Y, (int(c_client[i],16))%10**2) % _N) * (pow(_g0, Zx_client[i]) % _N)) % _N
        _val_cserver = str(_Y) + str(_Ts) + token[i]
        _cserver = hashlib.sha256(_val_cserver.encode('utf-8')).hexdigest()
        c_server.append(_cserver)
    return c_server

def tokenGenerator(n):
    ## Fungsi menghasilkan nilai token
    arr_token = []
    for i in range(1,n+1):
        arr_token.append(secrets.token_hex(32))
    return arr_token

def registerClient(conn_client):
    ## Fungsi menyimpan username client
    ## dan nilai zkp g dan y
    list_client = readClient()
    username = recvMessage(conn_client).decode("utf-8")
    if username in list_client.keys():
        sendMessage(conn_client, bytes('1', "utf-8"))
    else:
        sendMessage(conn_client, bytes('0', "utf-8"))
        auth_data = recvMessage(conn_client).decode("utf-8")
        ZKP_val = json.loads(auth_data.strip())
        user = {username:{'g':ZKP_val['g'],
                        'y':ZKP_val['y'],
                        'n':ZKP_val['n']}}
        list_client.update(user)
        writeClient(list_client)

def loginClient(conn_client):
    token = tokenGenerator(5)
    sendMessage(conn_client, bytes(json.dumps(token), "utf-8"))
    
    auth_data = json.loads(recvMessage(conn_client).decode("utf-8").strip())
    username = auth_data["username"]
    auth = auth_data["auth"] 
    fname = auth_data["fname"]=
    trf_msg = recvMessage(conn_client)    

    list_client = readClient()
    client = list_client[username] if username in list_client.keys() else None
    if client != None:

        _list_c_client = [auth[i][0] for i in range(len(auth))]
        _list_Zx_client = [auth[i][1] for i in range(len(auth))]
        _g0 = client["g"]
        _Y = client["y"]
        _N = client["n"]
        _list_c_server = __verifierZKP(_list_c_client, _list_Zx_client, _g0, _Y, _N, token)

        result = len(set(_list_c_server).intersection(_list_c_client))
        if (result/len(_list_c_server)) >= 0.8:
            CIPHER = AES.new(CIPHER_KEY, AES.MODE_EAX, NONCE)
            trf_msg = CIPHER.decrypt(trf_msg)
            writeFile(fname,trf_msg)
        else:
            print("message rejected")
    else:
        print("client not exist")

## FROM THIS LINE
## FUNCTION SERVER RUN
def multi_client_conn(conn_client,addr):
    while 1:
        data = recvMessage(conn_client).decode("utf-8")
        print(data)
        if data == '1':
            print(f"req : {addr} [Registration]")
            registerClient(conn_client)
        elif data == '2':
            print(f"req : {addr} [Send Message]")
            loginClient(conn_client)
        elif data == '3':
            break
    conn_client.close()

## FROM THIS LINE 
## MAIN PROGRAM
def main():
    s = socket.socket(socket.AF_INET, #Internet
        socket.SOCK_STREAM) #TCP
    s.bind((TCP_IP, TCP_PORT))
    s.listen(1)
    ThreadCount = 0

    while 1:
        conn , addr = s.accept()
        print('Connected to: ' + addr[0] + ':' + str(addr[1]))
        _thread.start_new_thread(multi_client_conn, (conn, addr))
        ThreadCount += 1
        print('Thread Number: ' + str(ThreadCount))
    s.close()
    

if __name__ == "__main__":
    main()
