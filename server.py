from socket import *
from threading import Thread
import pdb
import pickle
import ast

# command-line encrypt and decrypt demo:
# echo "secret message" | openssl rsautl -encrypt -pubin -inkey server_pub.pem | openssl rsautl -decrypt -inkey server_pri.pem

# generate public and private key file:
# prefix=name
# openssl genrsa -out "${prefix}_pri.pem" 2048
# openssl rsa -in "${prefix}_pri.pem" -outform PEM -pubout -out "${prefix}_pub.pem"

# when executing remember to terminate clients first
# otherwise the server socket will have a TIME_WAIT for about 30 seconds while it
# cleans up the connection

def readLines(sock, recv_buffer = 1024, delim='\n'):
    buffer = ''
    data = True

    while data:
        try:
            data = sock.recv(recv_buffer)
        except timeout:
            myPrint('User inactive, closing connection')
            return
        except ConnectionResetError:
            myPrint('Client closed connection')
            return
        except KeyboardInterrupt:
            myPrint('Process ending')
      
        buffer += data.decode()
        buffer = buffer.replace('\r','')
        while buffer.find(delim) != -1:
            line, buffer = buffer.split('\n',1)
            yield line
    return

def client_handler(client_socket, client_ip, client_port):
    print(f'New Connection from {client_ip}:{client_port}')

    g = readLines(client_socket)

    in_msg = g.__next__()
    client_name = in_msg[0:in_msg.find(":")]
    query = in_msg[in_msg.find(":")+2:]

    if(query != "get secret"):
        client_socket.send("Unknown query\n".encode())
        client_socket.close()
        return
    else:
        # check database, using a pickle file for simplicity right now
        database = None
        with open('database.pkl', 'rb') as f:
            database = pickle.load(f)
        if(client_name not in database.keys()):
            # client is not enrolled, tell them to enroll
            client_socket.send((f"{client_name} is not enrolled, " +
                               "send oscillation counts\n").encode())
            print("sent enrollment request")
            in_msg = g.__next__()
            database[client_name] = ast.literal_eval(in_msg)
            # update database
            with open('database.pkl', 'wb') as f:
                pickle.dump(database, f)
            client_socket.send("please reconnect\n".encode())
            print("told client to reconnect")
            client_socket.close()
            return
        else:
            # client is enrolled, challenge them
            pass

    client_socket.close()
    # for input_msg in readLines(client_socket):
    #     print(f"Received {input_msg} from {client_ip}:{client_port}")
    #     input_msg
    #     client_socket.send(response.encode())
    # client_socket.close()

if __name__ == "__main__":
    print("Server is running...")
    tcp_socket = socket(AF_INET, SOCK_STREAM)
    tcp_socket.bind(('', 0)) # bound to any IP address, any port
    tcp_port = tcp_socket.getsockname()[1]
    
    print("TCP socket has port number: " + str(tcp_port))
    try:
        while True:
            tcp_socket.listen(0)
            client_socket, client_info = tcp_socket.accept()
            client_ip = client_info[0]
            client_port = client_info[1]
            Thread(target=client_handler,
                   args=(client_socket, client_ip, client_port)).start()
    except KeyboardInterrupt:
        tcp_socket.close()
