#!/usr/bin/env python3
import os, fnmatch, binascii, sys
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from socket import *

ssh_keys ='client.keys/'
client_list = 'server.keys/clients'
host = 'localhost'
port = 22222

#Determines if file exists
def find_file(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            return True
        else:
            return False

#Pulls public key fof given client
def RSA_encryption(file):
    with open(file,'r') as f:
        data = f.read().replace('\\n', '\n')
    return data

#Encrpyts message using AES
def AES_encryption(iv, session_key, message):
    block_size=int(AES.block_size/2)
    ctr = Counter.new(block_size * 8, prefix=iv)
    aes = AES.new(session_key, AES.MODE_CTR, counter=ctr)
    enc_msg = aes.encrypt(message)
    return (enc_msg)

def main():
    while True:
        option = (input("\n1.Login into server.\n2.Generate ssh keys.\n\nOption 1 or 2: "))

        #Login to server.py
        if option == '1':
            user = str(input("Username: "))
            file_exist=find_file(user,ssh_keys)
            
            if file_exist ==False:
                print("Error: SSH key for usernmae does not exist")
            
            #Finds client public key, encrypts client name, and sends msg to server.py
            if file_exist == True:
                pubKey=RSA_encryption(ssh_keys+user+'.pub')
                pubKey=RSA.importKey(pubKey)
                enc_data = pubKey.encrypt(user.encode(), 32)[0]
                client_socket = socket(AF_INET, SOCK_STREAM)
                client_socket.connect((host, port))
                client_socket.send(enc_data)
                try:
                    serverMsg = client_socket.recv(1024)
                    print(serverMsg.decode("utf-8")+"\n")
                except:
                    client_socket.close()
                    continue
                
                #Receivies random session key genrated by server.py
                session_key = client_socket.recv(1024)
                iv = client_socket.recv(1024)
                
                while True:
                    clientMsg = input("Client: ")
                    
                    #exits and shutdown server.py and client.py program
                    if clientMsg == "quit()":
                        (enc_msg) = AES_encryption(iv, session_key, clientMsg)
                        client_socket.send((enc_msg))
                        client_socket.close()
                        sys.exit()
                    
                    #Swithces client
                    elif clientMsg == "change()":
                        (enc_msg) = AES_encryption(iv, session_key, clientMsg)
                        client_socket.send((enc_msg))
                        client_socket.close()
                        break
                    
                    #sends encrypted message to serv.py using AES
                    else:
                        (enc_msg) = AES_encryption(iv, session_key, clientMsg)
                        print("Encrypted Message:",enc_msg)
                        print("\n")
                        client_socket.send((enc_msg))
        
        #Generates random RSA ssh keys
        elif option == '2' :
            user = str(input("Username: "))
            keyPair = RSA.generate(1024)
            pubKey = keyPair.publickey()  
            pubKeyPEM = pubKey.exportKey()
            privKeyPEM = keyPair.exportKey()
            
            f = open(ssh_keys+user+'.pub', "w")
            f.write(pubKeyPEM.decode('ascii'))
            f.close()

            f = open('server.keys/'+user+'.pub', "w")
            f.write(pubKeyPEM.decode('ascii'))
            f.close()

            f = open(ssh_keys+user, "w")
            f.write(privKeyPEM.decode('ascii'))
            f.close()

            f = open(client_list, "a")
            f.write(user+"\n")
            f.close()

            print("SSH Key Successfully Generated")
            continue
        
        else:
            print("Error: Please try again")
            continue

                                           

if __name__ == '__main__':
    main()
    
