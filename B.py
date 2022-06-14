import threading
import socket
from RSAKeysLibrary import *
from os.path import exists
from queue import Queue
from Threads.ReceiveThread import *
from Threads.GuiThread import *


#  Sockets #czy nie da sie zrobic tego na jednu
HOST = socket.gethostbyname(socket.gethostname())  # jaworski mial 192.168.0.193, tu ip wpisać trzeba sprawdzić działa zawsze na 127.0.0.1 nie działa dla innych...
sendPORT = 8888
receivePORT = 8887
BUFFER = 4194304  # 2097152 # 1048576   # 1024

socketReceiveB = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET - socket family INET - ipv4 INET6 -ipv6
socketSendB = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET - socket family INET - ipv4 INET6 -ipv6

queue = Queue()


print("Starting " + 'B' + " GUI Thread")
socketReceiveB.bind((HOST, receivePORT))  # CONNECT TO SERVER
socketReceiveB.listen(2)  # liczba miejsc w kolejce
print("Starting " + 'B' + " receive thread")
socketSendB.connect((HOST, sendPORT))


socketReceiveB, address = socketReceiveB.accept()
print(f"Uzyskano polaczenie od {address} | lub {address[0]}:{address[1]}")

# --------------------------------- LOGOWANIE -----------------------------------------
password, command = password_popup_msg('B')
localKey = hashPassword(password)

if not exists('./KeysB/PublicKeys/publicKeyB.pem') or not exists('./KeysB/PrivateKeys/privateKeyB.pem') or command == "reset":
    generate_keys_secret('B', localKey)
publicKey, privateKey = load_keys_secret('B', localKey)

#  ---------------------------------Sending & Receiving Keys------------------------------
#  SEND PUBLIC KEY TO CLIENT (also receive key from client)
print("wysyłam klucz swój publiczny")
print("mój publicKey:" + str(publicKey))
#socketSendB.send(publicKey.save_pkcs1(format='PEM'))
socketSendB.send(publicKey.exportKey('PEM'))
print("mój klucz publiczny wysłany\n")

#  RECEIVE PUBLIC KEY FROM SERVER
#otherPublicKey = rsa.key.PublicKey.load_pkcs1(socketReceiveB.recv(BUFFER), format='PEM')  # DER
otherPublicKey = RSA.importKey(socketReceiveB.recv(BUFFER))
print("Otrzymano klucz publiczny:" + str(otherPublicKey))


# RECEIVE SESSION KEY FROM CLIENT   # 2 klucze sesyjne kazdy uzywa swojego do kodowania i drugiej strony do odkodowywania
print("odbieram session key\n")
receivedSessionKey = decrypt_session_key_with_rsa(socketReceiveB.recv(BUFFER), privateKey)
print("sessionKey: " + str(receivedSessionKey))


# ---------------------------------------------------------------Threads------------------------------------------------
# Create threads
receivingThreadB = threading.Thread(target=ReceiveThread, args=[1, 'B', socketReceiveB, BUFFER, queue, publicKey, privateKey, receivedSessionKey])
GUIThreadB = threading.Thread(target=GuiThread, args=[2, 'B', socketSendB, BUFFER, queue, publicKey, privateKey, otherPublicKey, receivedSessionKey])

# Start threads
receivingThreadB.start()
GUIThreadB.start()
