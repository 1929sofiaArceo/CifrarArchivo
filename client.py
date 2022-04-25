import socket
import os

SIZE = 1024
FORMAT = "utf-8"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((socket.gethostname(), 3000)) #port 3000
s.listen()
while True: #siempre estaremos escuchando nuevas conexiones
    client, address = s.accept()
    file = open("/Users/mac/Desktop/prueba.txt", "r")
    data = file.read()
    filename = os.path.basename(file.name)
    print("Client sending file: ", filename)
    print("connection from address: ", address, " succesfully established")
    client.send(data.encode(FORMAT))
    print("File sent!")
    file.close()
    client.close()