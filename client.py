from socket import *
from threading import Thread
import pdb
import os
from subprocess import Popen, PIPE
import argparse
import random
import numpy as np

# we can seed the oscillation counts based on the client username
# we will always have 16 oscillators, the server will save the oscillation
# counts and predict the result

def read_puf(name):
    random.seed(name)
    averages = [random.randint(500, 2000) for i in range(16)]
    result = []
    for i in range(16):
        # the averages are seeded but the sample is not
        # this simulates the randomness of each PUF
        sample = np.random.normal(averages[i], 50, 1)[0]
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

def send_to_server(tcp_socket, name, message):
    tcp_socket.sendall(message.encode())
    response = readLine(tcp_socket)
    print(f"received from server: {response}")
    return response
  
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The client PUF communicator")
    parser.add_argument("server_host", type=str,
                        help="The ip address (or hostname) of the server")
    args = parser.parse_args()
    
    name = input("Username: ")
    print(f"name = {name}")
    if(name.find("'") != -1 or name.find("\"") != -1):
        raise Exception("Quotes are not allowed in usernames!")
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

    tcp_port = "45819"

    # Check if we have a valid port

    tcp_socket = socket(AF_INET, SOCK_STREAM)
    # display the server's TCP Port number
    print("Server TCP Port: " + str(tcp_port))
    
    # open a TCP connection to the server.
    try:
        tcp_socket.connect((gethostbyname(host_ip), int(tcp_port.encode('utf-8'))))
        print("Client connected to server!")
    except:
        tcp_socket.close()
        raise Exception("Unable to connect to server")

    try:
        user_entry = input("Actions: 1. Query Server For Secret, 2. Exit\nChoice(1/2): ")
        if(user_entry == '1'):
            response = send_to_server(tcp_socket,
                                      name,
                                      f"{name}: get secret\n")
            print(f"response = {response}")
            if(response == f"{name} is not enrolled, send oscillation counts"):
                # send oscillation counts
                oscillations = read_puf(name)
                response = send_to_server(tcp_socket,
                                          name,
                                          str(oscillations) + "\n")
                if(response == "please reconnect"):
                    print("you have been enrolled, reconnect")
                    tcp_socket.close()
                    exit(0)
                else:
                    print("enrollment failure, please retry")
                    tcp_socket.close()
                    exit(0)
            else:
                pass
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
