import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from threading import Thread

class Server:
    def __init__(self, port=3001):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('0.0.0.0', port))
        self.server_socket.listen(5)
        self.server_ip = socket.gethostbyname(socket.gethostname())
        print(f"Server listening on {self.server_ip}:{port}")
        self.clients = {}  # Dictionary to store connected clients
        self.server_private_key = RSA.generate(2048)  # Generate server's RSA key pair

    def start(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Accepted connection from {addr}")

            # Handle the connection in a separate thread
            Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        try:
            # Receive the data from the client
            data_received = client_socket.recv(4096).decode('utf-8')

            # Split the received data into username and public_key
            username, public_key_data = data_received.split('\n', 1) if '\n' in data_received else (data_received, '')

            client_public_key = RSA.import_key(public_key_data.encode('utf-8'))

            # Store the client information
            self.clients[client_socket] = {'username': username, 'public_key': client_public_key}

            # Inform server that a new client has joined
            print(f"User '{username}' has joined.")

            # Send a response back to the client
            response_message = f">> {username} has joined."
            client_socket.send(response_message.encode('utf-8'))

            while True:
                encrypted_message = client_socket.recv(4096)

                if not encrypted_message:
                    break

                cipher = PKCS1_OAEP.new(self.server_private_key)
                decrypted_message = cipher.decrypt(encrypted_message).decode('utf-8')

                print(f"Received decrypted message from {username}: {decrypted_message}")

                for socket, client_info in self.clients.items():
                    if socket != client_socket:
                        try:
                            socket.send(f">> {username}: {decrypted_message}".encode('utf-8'))
                        except Exception as e:
                            print(f"Error sending message to {client_info['username']}: {str(e)}")

        except ValueError as ve:
            print(f"Error handling client: {ve}")

        except Exception as e:
            print(f"Error handling client: {str(e)}")

        finally:
            if client_socket in self.clients:
                del self.clients[client_socket]

            # Close the connection
            with client_socket:
                client_socket.close()

if __name__ == '__main__':
    server = Server(port=3001)
    server.start()