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
    
    keyFile = input("Enter filename for server public key: ")
    keyFile2 = input("Enter filename for client private key: ")
    
    with open(keyFile, mode='rb') as privatefile:
        keyData1 = privatefile.read()
    with open(keyFile2, mode='rb') as privatefile:
        keyData2 = privatefile.read()
    
    Server_pubkey = rsa.PublicKey.load_pkcs1(keyData1)
    Client_privkey = rsa.PrivateKey.load_pkcs1(keyData2)

    sock.connect((host, port))

    while 1:
        sendOrReceive = input("Upload or Download or Generate new keys(u/d/g?): ")
        sock.send(sendOrReceive.encode())
        
        if sendOrReceive == 'd':
            if cryptoType == 'symm':
                data = input("File to request from server: ")
                print()
                
                sock.send(data.encode())
                
                message_digest2 = sock.recv(4096)
                cipher = sock.recv(4096)
                
                print(f"Data received from server: {cipher}")
                print()
                
                plaintext = f.decrypt(cipher)
                hmac1.update(plaintext)
                message_digest = hmac1.digest()
    
                print(f"Is message integrity equal?: {hmac.compare_digest(message_digest, message_digest2)}")
                print(f"Decrypted data: {plaintext}")
                print()
            else:
                fileName = input("File to request from server: ")
                print()
                sock.send(fileName.encode())
                
                encrypted_data = sock.recv(4096)
                print(f"Data received from server: {encrypted_data}")
                print()
                
                signature = sock.recv(4096)
                print(f"Signature: {signature}")
                print()
                
                plaintext_data = rsa.decrypt(encrypted_data, Client_privkey)
                validity = "yes (SHA-512)" if rsa.verify(plaintext_data, signature, Server_pubkey) == "SHA-512" else "no"
                print(f"Decrypted data: {plaintext_data}")
                print()
                print(f"Valid signature: {validity}")
                print()
        elif sendOrReceive == 'u':
            if cryptoType == 'symm':
                data = input("File to send to server: ")
                print()
                
                plaintext = open(data, "rb")
                cipher = f.encrypt(plaintext.read())
                
                sock.send(cipher)
                print()
                
                plaintext.close()
            else:
                fileName = input("File to send to server: ")
                print()      
                plaintext_data = open(fileName, "rb")
                pt = plaintext_data.read()
                
                signature = rsa.sign(pt, Client_privkey, 'SHA-512')
                encrypted_data = rsa.encrypt(pt, Server_pubkey)
                sock.send(encrypted_data)
                sock.send(signature)
                print(f"Data sent to server: {encrypted_data}")
                print()
                print(f"Signature: {signature}")
                print()
                
                plaintext_data.close()
        elif sendOrReceive == 'g':
            cryptoType = input("Generate new asymmetric keys or new symmetric session key? (symm/asymm): ")
            sock.send(cryptoType.encode())
            
            if cryptoType == 'asymm':
                (Client_pubkey, Client_privkey) = rsa.newkeys(4096, poolsize=6)
                with open("C_pubkey.pem", "wb+") as f:
                    pubkey = rsa.PublicKey.save_pkcs1(Client_pubkey, format='PEM')
                    f.write(pubkey)
                with open("C_privkey.pem", "wb+") as f:
                    privkey = rsa.PublicKey.save_pkcs1(Client_privkey, format='PEM')
                    f.write(privkey)
                print(f"Done generating keys")
            elif cryptoType == 'symm':
                seed = input("Please enter a password (should be longer than 10 characters but does not need to be memorized): ")
                random.seed(seed)
                key = random.randint(10000000000000000000000000000000, 999999999999999999999999999999998)
                key2 = random.randint(10000000000000000000000000000000, 999999999999999999999999999999998)
                key = '{:32.32}'.format(str(key))
                key2 = str(key2)
                
                key1signature = rsa.sign(key.encode("utf-8"), Client_privkey, 'SHA-512')
                key1encrypted_data = rsa.encrypt(key.encode("utf-8"), Server_pubkey)
                key2signature = rsa.sign(key2.encode("utf-8"), Client_privkey, 'SHA-512')
                key2encrypted_data = rsa.encrypt(key2.encode("utf-8"), Server_pubkey)

                sock.send(key1signature)
                sock.send(key1encrypted_data)
                input(": ")
                sock.send(key2signature)
                sock.send(key2encrypted_data)
                
                key = bytes(key, encoding='utf8')
                key = base64.urlsafe_b64encode(key)
                
                f = Fernet(key)
                hmac1 = hmac.new(bytes(key2, encoding='utf8'), digestmod="sha3_256")
            else:
                exit()
        else:
            exit()
    sock.close()

if __name__ == "__main__":
    main()