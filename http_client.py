'''
    Implementation of simple HTTP client
'''

from random import randint
from socket import *
import pyDHE
from Crypto.Random import *
from Crypto.Cipher import AES

def get_hosturl_and_query():
    hosturl = input('Which URL do you want?: ')       
    while True:
        try:
            id, pwd = input("Enter your ID and password: ").split()
            break
        except:
            print('Invalid input. Try again\n')
            continue
    return hosturl, id, pwd

def get_cipher(key, ad, nonce):
    cipher = AES.new(key, AES.MODE_CCM, nonce)
    cipher.update(ad)
    return cipher

HOST = '127.0.0.1' # localhost
PORTNUM = 80
methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'EXIT']

with socket(AF_INET, SOCK_STREAM) as client_sock:
    client_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    client_sock.connect((HOST, PORTNUM))
    
    # DHE Process Start
    client = pyDHE.new()
    client_pubkey = client.getPublicKey()
    print("Client Public Key:",hex(client_pubkey))
    client_sock.sendall(str(client_pubkey).encode())
    
    server_pubkey = int(client_sock.recv(1024).decode())
    print("Server Public Key:",hex(server_pubkey))

    sharedkey = client.update(server_pubkey) % (1<<128)
    print("prev shared key: ", sharedkey)
    
    sharedkey = sharedkey.to_bytes(16, byteorder='little')
    print("\nShared Key:", sharedkey)
    # DHE Process End
    
    while True:
        # Share the Associated Data and Nonce
        ad = get_random_bytes(16)
        nonce = get_random_bytes(randint(7, 12))
        print("AD:", ad)
        print("Nonce:", nonce,'\n')

        client_sock.sendall(ad)
        client_sock.sendall(nonce)
        
        # Create a request
        request = ' / HTTP/1.1\r\nHOST: '
        # Get the method
        while True:
            try:
                method = int(input("Which Method do you want?\n1: GET\n2: POST\n3: HEAD\n4: PUT\n5: DELETE\n6: EXIT\n")) - 1
            except: 
                print("Input is not a number. Try again.\n")
                continue
            
            if method < len(methods):
                print("You requests", methods[method])
                break
            else: 
                print("Invalid method\n")
        
        request = methods[method] + request
        
        # Generate the client request header according to the method
        if methods[method] == 'GET':
            hosturl, id, pwd = get_hosturl_and_query()
            msg = "id=" + id + '&password=' + pwd
            request += hosturl + '?' + msg + '\r\n'
            request += 'Content-Length: ' + str(len(msg)) + '\r\n'
            
        elif methods[method] == 'POST':
            hosturl, id, pwd = get_hosturl_and_query()
            msg = "id=" + id + '&password=' + pwd
            request += hosturl + '\r\n'
            request += 'Content-Length: ' + str(len(msg)) + '\r\n'
            request += '\r\n' + msg
        
        elif methods[method] == 'PUT':
            hosturl = input('Which URL do you want?: ')       
            filename = input("Enter a file name: ")
            filedata = input("Enter a file data: ")
            
            request += hosturl + '\r\n'
            request += 'Content-Length: ' + str(len(filedata))
            request += '\r\n'
            request += 'Content-Disposition: form-data; filename=' + f'"{filename}"'
            request += "Content-Type: "
            if filename.endswith("txt"): request += "text/plain" 
            
            request += '\r\n\r\n' + filedata
                
        elif methods[method] == 'HEAD':
            hosturl = input('Which URL do you want?: ')       
            request += hosturl + '\r\n'
            
        elif methods[method] == 'DELETE':
            request = 'DELETE /file.html HTTP/1.1'
            
        elif methods[method] == 'EXIT':
            print("Exit the program")
            request = ' '
            client_sock.close()
            exit(1)
        
        # AES Setting
        encrypt = get_cipher(sharedkey, ad, nonce)
        
        # Encrypt the request
        encrypted_request, tag = encrypt.encrypt_and_digest(request.encode())
            
        # Send a request and tag and hash value
        print(f"\nClient Request: \n{request}")
        print("Encrypted req:", encrypted_request)
        client_sock.sendall(encrypted_request)
        print(f"Tag: {tag}")
        client_sock.sendall(tag)
        
        # Receive a server response and print
        recv = client_sock.recv(2048)
        tag = client_sock.recv(2048)
        
        decrypt = get_cipher(sharedkey, ad, nonce)
        
        decrypted_recv = decrypt.decrypt_and_verify(recv, tag)
        
        if decrypted_recv == b'':
            print("Empty Response\nConnection Failed")
            break
        else:
            response = decrypted_recv.decode()
            print(f"Response:\n{response}\n") 
#EOF
