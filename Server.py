#!/usr/bin/env python3

import random
import socket
import hmac
import hashlib
import base64
import rsa
from cryptography.fernet import Fernet

def main():
    port = 42424
    host = socket.gethostname()
    sock = socket.socket()
    sock.bind((host, port))
    
    with open("C_pubkey.pem", mode='rb') as privatefile:
        keyData1 = privatefile.read()
    with open("S_privkey.pem", mode='rb') as privatefile:
        keyData2 = privatefile.read()
    
    Client_pubkey = rsa.PublicKey.load_pkcs1(keyData1)
    Server_privkey = rsa.PrivateKey.load_pkcs1(keyData2)
    
    sock.listen(0)
    print("Listening for client")
    conn, address = sock.accept()

    print(f"Connection from: {str(address)}")
    print()

    while 1:
        sendOrReceive = conn.recv(4096).decode()
        
        if sendOrReceive == 'd':
            if cryptoType == 'symm':
                data = conn.recv(4096).decode()
            
                print(f"Data received from client: {data}")
                print()
                
                plaintext = open(data, "rb")
                pt = plaintext.read()
                
                hmac1.update(pt)
                message_digest = hmac1.digest()
                print(f"Message before encryption: {pt}")
                print(f"Message digest to send: {message_digest}")
                cipher = f.encrypt(pt)
                
                print(f"Data to send to client: {cipher}")
                print()
                
                conn.send(message_digest)
                conn.send(cipher)
                plaintext.close()
            else:
                fileName = conn.recv(4096).decode()
                print(f"Data received from client: {fileName}")
                print()
                
                plaintext_data = open(fileName, "rb")
                pt = plaintext_data.read()
                data_encrypted = rsa.encrypt(pt, Client_pubkey)
                signature = rsa.sign(pt, Server_privkey, 'SHA-512')
                
                print(f"Data to send to client: {data_encrypted}")
                print()
                print(f"Signature: {signature}")
                print()
                conn.send(data_encrypted)
                conn.send(signature)
                
                plaintext_data.close()
        elif sendOrReceive == 'u':
            if cryptoType == 'symm':
                cipher = conn.recv(4096).decode()
            
                print(f"Data received from client: {cipher}")
                print()
                
                plaintext = f.decrypt(cipher)
                print(f"Decrypted data: {plaintext}")
                print()
            else:
                encrypted_data = conn.recv(4096)
                print(f"Data received from client: {encrypted_data}")
                print()
                
                signature = conn.recv(4096)
                print(f"Signature: {signature}")
                print()
                
                plaintext_data = rsa.decrypt(encrypted_data, Server_privkey)
                validity = "yes (SHA-512)" if rsa.verify(plaintext_data, signature, Client_pubkey) == "SHA-512" else "no"
                print(f"Decrypted data: {plaintext_data}")
                print()
                print(f"Valid signature: {validity}")
                print()
        elif sendOrReceive == 'g':
            cryptoType = conn.recv(4096).decode()
            
            if cryptoType == 'asymm':
                (Server_pubkey, Server_privkey) = rsa.newkeys(4096, poolsize=6)
                with open("S_pubkey.pem", "wb+") as f:
                    pubkey = rsa.PublicKey.save_pkcs1(Server_pubkey, format='PEM')
                    f.write(pubkey)
                with open("S_privkey.pem", "wb+") as f:
                    privkey = rsa.PublicKey.save_pkcs1(Server_privkey, format='PEM')
                    f.write(privkey)
                print(f"Done generating keys")
            elif cryptoType == 'symm':
                key1signature = conn.recv(4096)
                key1encrypted_data = conn.recv(4096)
                key2signature = conn.recv(4096)
                key2encrypted_data = conn.recv(4096)
                
                print(f"Valid?")
                key1plaintext_data = rsa.decrypt(key1encrypted_data, Server_privkey)
                key1validity = "key1: yes (SHA-512)" if rsa.verify(key1plaintext_data, key1signature, Client_pubkey) == "SHA-512" else "no"
                print(f"Valid signature: {key1validity}")
                key2plaintext_data = rsa.decrypt(key2encrypted_data, Server_privkey)
                key2validity = "key2: yes (SHA-512)" if rsa.verify(key2plaintext_data, key2signature, Client_pubkey) == "SHA-512" else "no"
                print(f"Valid signature: {key2validity}")

                key1plaintext_data = base64.urlsafe_b64encode(key1plaintext_data)
                key2plaintext_data = str(key2plaintext_data)
                
                f = Fernet(key1plaintext_data)
                hmac1 = hmac.new(bytes(key2plaintext_data, encoding='utf8'), digestmod="sha3_256")
            else:
                exit()
        else:
            exit()
    conn.close()

if __name__ == "__main__":
    main()