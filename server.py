from socket import *
from threading import Thread
import pdb
import pickle
import ast
import random
import argparse
import os
from subprocess import Popen, PIPE

# command-line encrypt and decrypt demo:
# echo "secret message" | openssl rsautl -encrypt -pubin -inkey server_pub.pem | openssl rsautl -decrypt -inkey server_pri.pem

# generate public and private key file:
# prefix=name
# openssl genrsa -out "${prefix}_pri.pem" 2048
# openssl rsa -in "${prefix}_pri.pem" -outform PEM -pubout -out "${prefix}_pub.pem"

# when executing remember to terminate clients first
# otherwise the server socket will have a TIME_WAIT for about 30 seconds while it
# cleans up the connection

def encrypt(client_name, plaintext):
    # need single quotes to avoid expansion in bash
    # use bash to encrypt, convert binary output to hex
    command = f"echo -n '{plaintext}' | "
    command += f"openssl rsautl -encrypt -pubin -inkey {client_name}_pub.pem | "
    command += r"xxd -u -p | tr -d '\n'"
    stream = os.popen(command)
    cyphertext = stream.read()
    return cyphertext

def decrypt(cyphertext):
    # need single quotes to avoid expansion in bash
    # use bash to convert hex to raw binary, decrypt this binary into plaintext
    command = f"echo -n '{cyphertext}' | "
    command += "xxd -r -p | "
    command += "openssl rsautl -decrypt -inkey server_pri.pem"
    stream = os.popen(command)
    plaintext = stream.read()
    return plaintext

def send_to_client(client_socket, client_name, message, generator, do_encrypt):
    if(do_encrypt):
        message = encrypt(client_name, message)
    client_socket.send((message + "\n").encode())
    try:
        response = generator.__next__()
    except:
        # if no response then continue anyway
        response = ""
    if(do_encrypt and len(response) > 0):
        response = decrypt(response)
    return response

def readLines(sock, recv_buffer = 1024, delim='\n'):
    buffer = ''
    data = True

    while data:
        try:
            data = sock.recv(recv_buffer)
        except timeout:
            print('User inactive, closing connection')
            return
        except ConnectionResetError:
            print('Client closed connection')
            return
        except KeyboardInterrupt:
            print('Process ending')
      
        buffer += data.decode()
        buffer = buffer.replace('\r','')
        while buffer.find(delim) != -1:
            line, buffer = buffer.split('\n',1)
            yield line
    return

def client_handler(client_socket, client_ip, client_port, do_encrypt):
    print(f'New Connection from {client_ip}:{client_port}')

    g = readLines(client_socket)

    in_msg = g.__next__()
    if(do_encrypt):
        in_msg = decrypt(in_msg)
    client_name = in_msg[0:in_msg.find(":")]
    query = in_msg[in_msg.find(":")+2:]

    if(query != "get secret"):
        send_to_client(client_socket, client_name, "unknown query", g, do_encrypt)
        client_socket.close()
        return
    else:
        # check database, using a pickle file for simplicity right now
        database = None
        with open('database.pkl', 'rb') as f:
            database = pickle.load(f)
        if(client_name not in database.keys()):
            # client is not enrolled, tell them to enroll
            in_msg = send_to_client(client_socket, client_name,
                           (f"{client_name} is not enrolled, " +
                            "send oscillation list"), g, do_encrypt)
            print("sent enrollment request")
            database[client_name] = ast.literal_eval(in_msg)
            # update database
            with open('database.pkl', 'wb') as f:
                pickle.dump(database, f)
            send_to_client(client_socket, client_name, "please reconnect", g, do_encrypt)
            print("told client to reconnect")
            client_socket.close()
            return
        else:
            # client is enrolled, challenge them
            oscillators = database[client_name]
            for i in range(16):
                oscillators[i] = (oscillators[i], i)
            # sort based on oscillation count
            oscillators = sorted(oscillators, key=lambda y: y[0])
            slow_oscillators = [] # indices of slow oscillators
            fast_oscillators = [] # indices of fast oscillators

            for i in range(16):
                if(i < 8):
                    slow_oscillators.append(oscillators[i][1])
                else:
                    fast_oscillators.append(oscillators[i][1])
            random.shuffle(slow_oscillators)
            random.shuffle(fast_oscillators)

            expected = ""
            challenge = []
            for i in range(8):
                # need a coin flip, to decide the order of the pair
                coin_flip = random.randint(0, 1)
                count1 = slow_oscillators[i]
                count2 = fast_oscillators[i]
                if(coin_flip == 0):
                    # slow comes first
                    challenge.append((count1, count2))
                    if(count1 == count2):
                        expected += "1"
                    else:
                        expected += "0"
                else:
                    # fast comes first
                    challenge.append((count2, count1))
                    expected += "1"

            print(f"saved enroll sig: {database[client_name]}")
            print(f"expected chall answer: {expected}")
            in_msg = send_to_client(client_socket, client_name,
                           (f"{client_name} is enrolled, " +
                            f"answer challenge: {challenge}"), g, do_encrypt)
            bit_string = in_msg
            if(bit_string == expected):
                # auth success
                with open('secret.txt') as f:
                    secret = f.read()
                    send_to_client(client_socket, client_name,
                                   ("authentication success, secret " +
                                    f"is: {secret}"), g, do_encrypt)
                    client_socket.close()
                    return
            else:
                # auth failure
                send_to_client(client_socket, client_name,
                               "authentication failure, try again",
                               g, do_encrypt)
                client_socket.close()
                return

    client_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The server PUF communicator")
    parser.add_argument("port", type=int,
                        help="tcp port number, use 0 to any available port")
    parser.add_argument("--encrypt", dest="encrypt", action="store_true",
                        help="set this option to encrypt all traffic")
    args = parser.parse_args()
    
    print("Server is running...")
    tcp_socket = socket(AF_INET, SOCK_STREAM)
    tcp_socket.bind(('', args.port)) # bound to any IP address, any port
    tcp_port = tcp_socket.getsockname()[1]
    
    print("TCP socket has port number: " + str(tcp_port))
    try:
        while True:
            tcp_socket.listen(0)
            client_socket, client_info = tcp_socket.accept()
            client_ip = client_info[0]
            client_port = client_info[1]
            Thread(target=client_handler,
                   args=(client_socket, client_ip, client_port, args.encrypt)).start()
    except KeyboardInterrupt:
        tcp_socket.close()
