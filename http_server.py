'''
    Implementation of a simple HTTP server
'''

from socket import *
import os
from datetime import datetime
import pyDHE
from timeit import *
from Crypto.Cipher import AES

HOST = '127.0.0.1' # localhost
PORTNUM = 80
TIMEOUT_CHECK_SEC = 2
entire_files = []

def checkping(response: str, ping, elapsed_time):
    # if ping successes
    if ping == 0: 
        response += '200 OK\r\n'
    # if ping fails
    else:
        if elapsed_time < TIMEOUT_CHECK_SEC:
            response += '400 Bad Request\r\n'
        else: 
            response += '408 Request Timeout\r\n'
    return response

def get_cipher(key, ad, nonce):
    cipher = AES.new(key, AES.MODE_CCM, nonce)
    cipher.update(ad)
    return cipher

def get_filelist():
    global entire_files
    filename = 'C:/Users/coalab/Documents/python_coding/Network_socket/filelist.txt'
    with open(filename, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for line in lines:
            entire_files.append(line.strip())
    return entire_files

# Generate header lines and body
def generate_response_headerlines():
    day = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    month = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    
    headerlines  = 'Date: ' + day[datetime.today().weekday()] + ', ' + str(datetime.now().day)
    headerlines += ' ' + month[datetime.now().month - 1] + ' '
    headerlines += datetime.today().strftime("%Y %H:%M:%S") + ' GMT\r\n'
    return headerlines

# Send a ping and return (ping, elapsed time)
def send_ping(URL: str):
    start_time = default_timer()
    ping = os.system("ping -n 1 " + URL)
    end_time = default_timer()
    elapsed_time = end_time - start_time
    
    return ping, elapsed_time

# Each functions send a ping to recieved URL and decides the status code
def GET_method(request: str, response: str): # finish
    # Send a ping
    URL = request[request.find('HOST: ')+6 : request.find('?')].strip()
    print(f"Connecting to {URL}...")
    ping, elapsed_time = send_ping(URL)
    
    response = checkping(response, ping, elapsed_time)
    response += 'Content-type: text/html\r\n'
    response += 'Content-Length: ' + str(len(request[request.find('?') : request.find('\r')])) + '\r\n'
    headerline = generate_response_headerlines()
    
    return response + headerline

def POST_method(request: str, response: str):
    # Send a ping
    URL = request[request.find('HOST: ')+6:].strip()
    print(f"Connecting to {URL}...")
    ping, elapsed_time = send_ping(URL)
        
    response = checkping(response, ping, elapsed_time)   
    response += 'Content-type: text/html\r\n'
    response += 'Content-Length: ' + str(len(request[request.find('\r\n\r\n') : ])) + '\r\n'
    headerline = generate_response_headerlines()
    
    return response + headerline + '\r\n'

def PUT_method(request: str, response: str): 
    # Send a ping
    URL = request[request.find('HOST: ')+6 : request.find("Content-Length")].strip()
    print(f"Connecting to {URL}...")
    ping, elapsed_time = send_ping(URL)

    # create file, file check
    filename = request[request.find("filename=")+10 : request.find("Content-Type")-1]
    filedir = 'C:/Users/coalab/Documents/python_coding/Network_socket/'
    file = filedir + filename
    
    # write the data into the file, and append to DB
    with open(file, 'w', encoding='utf-8') as f:
        filedata = request[request.find('\r\n\r\n'):].strip()
        f.write(filedata)
        entire_files.append(filename)
        
    # update the DB
    entire_files_dir = filedir + 'filelist.txt'
    with open(entire_files_dir, 'w', encoding='utf-8') as f:
        for i in entire_files:
            f.write(i+'\n')
        
    print(entire_files)
        
    response = checkping(response, ping, elapsed_time)  
    response += 'Content-type: text/html\r\n'
    response += 'Content-Length: ' + str(len(filedata)) + '\r\n'
    headerline = generate_response_headerlines()
    
    return response + headerline + '\r\n'

def HEAD_method(request: str, response: str):
    # Send a ping
    URL = request[request.find('HOST: ')+6 : request.find('?')].strip()
    print(f"Connecting to {URL}...")
    ping, elapsed_time = send_ping(URL)
    
    response = checkping(response, ping, elapsed_time)
    headerline = generate_response_headerlines()

    return response + headerline

def DELETE_method(request: str, response: str):
    filedir = 'C:/Users/coalab/Documents/python_coding/Network_socket/'
    try:
        file = filedir + entire_files[-1]
        os.remove(file)
        del entire_files[-1]
        entire_files_dir = filedir + 'filelist.txt'
        with open(entire_files_dir, 'w', encoding='utf-8') as f:
            for i in entire_files:
                f.write(i+'\n')
    # Deleting an already deleted item is succesful
    # The else statement below doesn't have any function
    # but expressed them explicitly to make the purpose obvious 
    except:
        pass
    response += '204 No Content\r\n'
    headerline = generate_response_headerlines()

    return response + headerline
    
# If request method cannot be supported -> ERROR
def INVAILD_method(response: str, ssock: socket, csock: socket):
    csock.close()
    ssock.close()
    print("Invaild Method")
    
    
##########################################################################################

# Create server socket
server_sock = socket(AF_INET, SOCK_STREAM)
server_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1) # For WinError 10048
server_sock.bind((HOST, PORTNUM))
server_sock.listen(1)
print(f"Listening on port number {PORTNUM}")

# Waiting for client connection
client_sock, client_addr = server_sock.accept()
print(f"Connected: {client_addr}")

# DHE Process   
server = pyDHE.new()
server_pubkey = server.getPublicKey()
print("Server Public Key:",hex(server_pubkey))
client_sock.sendall(str(server_pubkey).encode())
    
client_pubkey = int(client_sock.recv(1024).decode())
print("Client Public Key:",hex(client_pubkey))

sharedkey = server.update(client_pubkey) % (1<<128)
print("prev shared key: ", sharedkey)
sharedkey = sharedkey.to_bytes(16, byteorder='little')
print("\nShared Key:", sharedkey)
print("Key len:", len(bytes(sharedkey)))
# DHE Process End

entire_files = get_filelist()

while True:
    # Receive the Associated Data and Nonce from client
    ad = client_sock.recv(16)
    nonce = client_sock.recv(16)
    print("AD:", ad)
    print("Nonce:", nonce)
    
    # Get client request(encrypted)
    encrypted_request = client_sock.recv(1024)
    tag = client_sock.recv(1024)
    print("Encrypted req:", encrypted_request)
    print("Tag:", tag)
    
    # AES Setting
    decrypt = get_cipher(sharedkey, ad, nonce)
    
    # Decrypt the request
    try:
        request = decrypt.decrypt_and_verify(encrypted_request, tag).decode()
    except:
        print("ERROR DETECTED")
        break
    
    # Check the request length is 0
    if not request: break
    print(f"Request: \n{request}")

    # Set HTTP response
    response = 'HTTP/1.1 '
    
    # Check the method and make a response
    if   request.startswith('GET'):    response = GET_method(request, response)
    elif request.startswith('PUT'):    response = PUT_method(request, response)
    elif request.startswith('POST'):   response = POST_method(request, response)
    elif request.startswith('HEAD'):   response = HEAD_method(request, response)
    elif request.startswith('DELETE'): response = DELETE_method(request, response)
    else:      
        client_sock.close()
        server_sock.close()
        exit(1)
        
    # AES Setting
    encrypt = get_cipher(sharedkey, ad, nonce)
    encrypted_response, tag = encrypt.encrypt_and_digest(response.encode())
    
    # Send Encrypted response, tag and hash value
    client_sock.sendall(encrypted_response)      
    client_sock.sendall(tag)
    print("Encrypted response:", encrypted_response)
    print("Tag:", tag)

# Close sockets
client_sock.close()
server_sock.close()
#EOF
