from socket import *
from threading import Thread
import pdb

# command-line encrypt and decrypt demo:
# echo "secret message" | openssl rsautl -encrypt -pubin -inkey server_pub.pem | openssl rsautl -decrypt -inkey server_pri.pem

# generate public and private key file:
# prefix=name
# openssl genrsa -out "${prefix}_pri.pem" 2048
# openssl rsa -in "${prefix}_pri.pem" -outform PEM -pubout -out "${prefix}_pub.pem"

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
    for input_msg in readLines(client_socket):
        print(f"Received {input_msg} from {client_ip}:{client_port}")
        response = "hello there :-)\n"
        client_socket.send(response.encode())
    client_socket.close()

if __name__ == "__main__":
    print("Server is running...")
    tcp_socket = socket(AF_INET, SOCK_STREAM)
    tcp_socket.bind(('', 639)) # bound to any IP address, on port 639
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
