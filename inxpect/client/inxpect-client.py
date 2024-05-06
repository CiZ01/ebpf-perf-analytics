import ctypes as ct
import struct
import socket as s
from time import sleep

class InxpectUnion(ct.Union):
    _fields_ = [
        ("buffer", ct.POINTER(ct.c_char)),
        ("value", ct.c_int),
    ]

class InxpectMessage(ct.Structure):
    _fields_  = [
        ("type", ct.c_int),
        ("ret", InxpectUnion)
    ]

class InxpectClient:
    def __init__(self, server_address, server_port):
        self.server_address = server_address
        self.server_port = server_port
        self.client_socket = None
    
    def __to_struct__(self, dataStruct):
        struct.pack('i256s', dataStruct.type, )

    def connect(self):
        self.client_socket = s.socket(s.AF_INET, s.SOCK_STREAM)
        self.client_socket.connect((self.server_address, self.server_port))
        print("Connesso al server")

    def send_message(self, message):
        self.client_socket.send(message)
        print("Messaggio inviato al server")
        
    def receive_message(self):
        try:
           #message = InxpectMessage()
           # buf = ct.create_string_buffer(7)
           # message.ret.buffer = ct.cast(buf, ct.POINTER(ct.c_char))
             
            data = self.client_socket.recv(ct.sizeof(InxpectMessage()))
            if not data:
                return
            
            message = InxpectMessage.from_buffer_copy(data)
            
            print("Messaggio ricevuto dal server - Tipo:", message.type)
        
        
            # Lettura del valore dal buffer di caratteri

            print("Valore ricevuto dal server:", message.ret.buffer[0])
            
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
    
    union = InxpectUnion()
    union.value = 99
    message = InxpectMessage(1, union)
    client.send_message(message)
   
   
   #print("Messaggio da inviare al server:", message.type, message.value) 
       
    
    client.receive_message()

    client.close()