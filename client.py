from socket import *
from threading import Thread
import pdb
import os
from subprocess import Popen, PIPE
import argparse
import random
import numpy as np
import ast
import pickle

# we can seed the oscillation counts based on the client username
# we will always have 16 oscillators, the server will save the oscillation
# counts and predict the result

def encrypt(plaintext):
    # need single quotes to avoid expansion in bash
    command = f"echo -n '{plaintext}' | "
    command += f"openssl rsautl -encrypt -pubin -inkey server_pub.pem | "
    command += r"xxd -u -p | tr -d '\n'"
    stream = os.popen(command)
    cyphertext = stream.read()
    return cyphertext

def decrypt(name, cyphertext):
    # need single quotes to avoid expansion in bash
    command = f"echo -n '{cyphertext}' | "
    command += "xxd -r -p | "
    command += f"openssl rsautl -decrypt -inkey {name}_pri.pem"
    stream = os.popen(command)
    plaintext = stream.read()
    return plaintext

def read_puf(puf_seed):
    random.seed(puf_seed)
    averages = [random.randint(500, 2000) for i in range(16)]
    print(f"puf_averages = {averages}")
    result = []
    for i in range(16):
        # the averages are seeded but the sample is not
        # this simulates the randomness of each PUF
        # std is 15 here, is this reasonable?
        sample = np.random.normal(averages[i], 15, 1)[0]
        sample = int(sample)
        result.append(sample)
    return result

def readLine(sock, recv_buffer = 1024, delim='\n'):
    global buffer
  
    while True:
        data = sock.recv(recv_buffer)
        buffer += data.decode()
        buffer = buffer.replace('\r','')
        while buffer.find(delim) != -1:
            line, buffer = buffer.split('\n',1)
            return line
    return

def send_to_server(tcp_socket, message, name, do_encrypt):
    print(f"sending to server: {message.strip()}")
    if(do_encrypt):
        message = encrypt(message)
    tcp_socket.sendall((message + "\n").encode())
    response = readLine(tcp_socket)
    if(do_encrypt):
        response = decrypt(name, response)
    print(f"received from server: {response}\n")
    return response
  
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The client PUF communicator")
    parser.add_argument("server_host", type=str,
                        help="The ip address (or hostname) of the server")
    parser.add_argument("port", type=int,
                        help="server tcp port to connect to")
    parser.add_argument("--encrypt", dest="encrypt", action="store_true",
                        help="set this option to encrypt all traffic")
    args = parser.parse_args()
    
    name = input("Username: ")
    if(name.find("'") != -1 or name.find("\"") != -1):
        raise Exception("Quotes are not allowed in usernames!")
    new_puf = input("Do you want to create a new PUF?(yes/no): ")
    new_puf = new_puf.lower()
    puf_seed = None
    if(new_puf == "yes"):
        puf_seed = random.randint(0, 1000000)
        with open(f"{name}.puf", "wb") as f:
            pickle.dump(str(puf_seed), f)
    else:
        if(not os.path.exists(f"{name}.puf")):
            print("PUF not found for user, creating one")
            puf_seed = random.randint(0, 1000000)
            with open(f"{name}.puf", "wb") as f:
                pickle.dump(puf_seed, f)
        else:
            with open(f"{name}.puf", "rb") as f:
                puf_seed = int(pickle.load(f))
    print(f"puf_seed = {puf_seed}")
    if(os.path.exists(f"{name}_pri.pem") and
       os.path.exists(f"{name}_pub.pem")):
        # user has their key files in the current directory, continue
        pass
    else:
        print("Your public and private key files were not found " +
              "in this directory.")
        response = input("Do you wish to create them now?(yes/no): ")
        response = response.lower()
        if(response == 'yes'):
            command = f"prefix={name};"
            command += "openssl genrsa -out \"${prefix}_pri.pem\" 2048;"
            command += "openssl rsa -in \"${prefix}_pri.pem\" -outform "
            command += "PEM -pubout -out \"${prefix}_pub.pem\""
            stream = os.popen(command)
            stream.read()
            if(os.path.exists(f"{name}_pri.pem") and
               os.path.exists(f"{name}_pub.pem")):
                print("Key file generation success")
            else:
                raise Exception("Unable to generate key files")
        elif(response == 'no'):
            print("Good Bye.")
            exit(0)
        else:
            raise Exception("Invalid Response")
            
    # connect to server here
    global buffer
    buffer = ""
      
    # Get IP address of server via DNS and print it
    host_ip = gethostbyname(args.server_host)
    print("Server IP: " + str(host_ip))

    tcp_port = str(args.port)

    # Check if we have a valid port

    tcp_socket = socket(AF_INET, SOCK_STREAM)
    # display the server's TCP Port number
    # print("Server TCP Port: " + str(tcp_port))
    
    # open a TCP connection to the server.
    try:
        tcp_socket.connect((gethostbyname(host_ip), int(tcp_port.encode('utf-8'))))
        print("Client connected to server!")
    except:
        tcp_socket.close()
        raise Exception("Unable to connect to server")

    try:
        user_entry = input("Actions: 1. Query Server For Secret, 2. Exit\nChoice(1/2): ")
        print()
        if(user_entry == '1'):
            response = send_to_server(tcp_socket,
                                      f"{name}: get secret",
                                      name,
                                      args.encrypt)
            if(response == f"{name} is not enrolled, send oscillation list"):
                # send oscillation counts
                oscillations = read_puf(puf_seed)
                response = send_to_server(tcp_socket,
                                          str(oscillations),
                                          name,
                                          args.encrypt)
                if(response == "please reconnect"):
                    tcp_socket.close()
                    exit(0)
                else:
                    raise Exception("Server side error")
                    tcp_socket.close()
                    exit(0)
            else:
                # user is enrolled, string should be a challenge
                challenge = response[response.find(':')+2:]
                challenge = ast.literal_eval(challenge)
                puf_reading = read_puf(puf_seed)
                bit_string = ""
                for pair in challenge:
                    index1 = pair[0]
                    index2 = pair[1]
                    print(f"puf({index1}) cmp puf({index2}) -- {puf_reading[index1]} cmp {puf_reading[index2]}")
                    if(puf_reading[index1] >= puf_reading[index2]):
                        bit_string += "1"
                    else:
                        bit_string += "0"
                response = send_to_server(tcp_socket,
                                          f"{bit_string}",
                                          name,
                                          args.encrypt)
        elif(user_entry == '2'):
            print("Good Bye.")
            tcp_socket.close()
            exit(0)
        else:
            tcp_socket.close()
            raise Exception("Invalid Input")
        
    except KeyboardInterrupt:
        tcp_socket.close()

    tcp_socket.close()
