#!/usr/bin/env python3
import os, fnmatch, binascii, sys
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from socket import *

client_list='server.keys/clients'
path = 'client.keys/'
host = 'localhost'
port = 22222
key_bytes = 32

#Determines if file exists
def find_file(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            return True
        else:
            return False

#Pulls private key for given client
def RSA_decryption(file):
    with open(file,'r') as f:
        data = f.read().replace('\\n', '\n')
    return data

#Decrpyts message using AES
def AES_decryption(session_key, iv, ciphertext):
    block_size=int(AES.block_size/2)
    ctr = Counter.new(block_size * 8, prefix=iv)
    aes = AES.new(session_key, AES.MODE_CTR, counter=ctr)
    msg = aes.decrypt(ciphertext)
    return msg.decode("utf-8") 


def main():

    #Initate server socket and wait for client to connect
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(10)
    print("[*] Listening at %s" % (str(server_socket.getsockname())))
    print("[*] Ready to chat with a new client!")
    connection, address = server_socket.accept()
    print("[*] Connected socket between %s and %s"%(connection.getsockname(), connection.getpeername()))
    enc_data=connection.recv(1024)
    
    #Finds corresponding private keys to decrypt client name and autenticate client
    f= open(client_list,'r',)
    for line in f:
        line = line.strip()
        exist=find_file(line,path)
        if exist is True:
            privateKey=RSA_decryption(path+line)
            privateKey=RSA.importKey(privateKey)
            try:
                dec_data = privateKey.decrypt(enc_data).decode()
            except:
                continue
            if line == (dec_data):
                serverMsg=b'Authentication Successful!'
                connection.send(serverMsg)
                session_key = Random.new().read(key_bytes)
                connection.send((session_key))
                block_size = int(AES.block_size/2)
                iv = Random.new().read(block_size)
                connection.send((iv))
                break 
        

    while True:
        #Recieves encrypted message from client.py
        clientMsg = connection.recv(1024)
        print("Encrypted Message:",clientMsg)
        clientMsg = AES_decryption(session_key,iv,clientMsg)
        
        #Closes connection
        if clientMsg == "quit()":
            print( "Client: %s" % (clientMsg))
            print("[*] Closing connection between %s and %s"%(connection.getsockname(), connection.getpeername()))
            connection.close()
            sys.exit()

        #Restarts server to accept new client
        elif clientMsg == "change()":
            print( "Client: %s" % (clientMsg))
            print("[*] Closing connection between %s and %s"%(connection.getsockname(), connection.getpeername()))
            connection.close()
            server_socket.close()
            main()
        
        #Outputs decrypted message
        else:
            print( "Decrypted Message: %s \n" % (clientMsg))
            
if __name__ == '__main__':
    main()
