import ctypes as ct
import socket as s

class InxpectClient:
    def __init__(self, server_address, server_port):
        self.server_address = server_address
        self.server_port = server_port
        self.client_socket = None

    def connect(self):
        self.client_socket = s.socket(s.AF_INET, s.SOCK_STREAM)
        self.client_socket.connect((self.server_address, self.server_port))
        print("Connesso al server")

    def send_message(self, message):
        self.client_socket.sendall(message.encode())
        print("Messaggio inviato al server")
        
    def receive_message(self):
        try:
            data = self.client_socket.recv(1024)
            if not data:
                return
            print("Messaggio ricevuto dal server:", data.decode())
        except Exception as e:
            print("Errore durante la ricezione del messaggio:", str(e))
            

    def close(self):
        self.client_socket.close()
        print("Connessione chiusa")
        
if __name__ == "__main__":
    server_address = "0.0.0.0"  # Indirizzo IP del server
    server_port = 8080  # Porta del server

    client = InxpectClient(server_address, server_port)
    client.connect()

    message = ct.c_int(0).value
    client.send_message(message)
    
    client.receive_message()

    client.close()