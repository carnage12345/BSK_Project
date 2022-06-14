import threading
import socket
from RSAKeysLibrary import *
from os.path import exists
from queue import Queue
from Threads.ReceiveThread import *
from Threads.GuiThread import *


#  Sockets
HOST = socket.gethostbyname(socket.gethostname())  # '192.168.0.193'  # jaworski mial 192.168.0.193 # tu ip wpisać trzeba sprawdzić działa zawsze na 127.0.0.1 nie działa dla innych...
receivePORT = 8888
sendPORT = 8887
BUFFER = 4194304  # 2097152 # 1048576   # 1024   # 4mb

socketReceiveA = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET - socket family INET - ipv4 INET6 -ipv6
socketSendA = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET - socket family INET - ipv4 INET6 -ipv6


queue = Queue()

print("Starting " + 'A' + " GUI Thread")
socketSendA.connect((HOST, sendPORT))

print("Starting " + 'A' + " receive thread")
socketReceiveA.bind((HOST, receivePORT))  # CONNECT TO SERVER
socketReceiveA.listen(2)  # liczba miejsc w kolejce

socketReceiveA, address = socketReceiveA.accept()
print(f"Uzyskano polaczenie od {address} | lub {address[0]}:{address[1]}")


# --------------------------------- RSA KEYS -----------------------------------------
password, command = password_popup_msg('A')
localKey = hashPassword(password)

if not exists('./KeysA/PublicKeys/publicKeyA.pem') or not exists('./KeysA/PrivateKeys/privateKeyA.pem') or command == "reset":
    generate_keys_secret('A', localKey)
publicKey, privateKey = load_keys_secret('A', localKey)




#  ---------------------------------Sending & Receiving Keys------------------------------
#  RECEIVE PUBLIC KEY FROM B
#otherPublicKey = rsa.key.PublicKey.load_pkcs1(socketReceiveA.recv(BUFFER), format='PEM')  # DER
otherPublicKey = RSA.importKey(socketReceiveA.recv(BUFFER))
print("Otrzymano klucz publiczny:" + str(otherPublicKey))

#  SEND PUBLIC KEY TO B
print("wysyłam klucz do Serwera")
print(publicKey)
#socketSendA.send(publicKey.save_pkcs1(format='PEM'))
socketSendA.send(publicKey.exportKey('PEM'))
print("klucz wysłany\n")


#  SESSION KEY
print("CREATING SESSION KEY:")
sessionKey = os.urandom(16)  # sessionKey = b'mysecretpassword'  # 16 byte password

# SEND SESSION KEY TO SERVER
print("sending session KEY")
print(sessionKey)
ciphertext = encrypt_session_key_with_rsa(sessionKey, otherPublicKey)  # zamienic na sessionKey3Random

socketSendA.send(ciphertext) #dorobić
print("sent session KEY\n")


# ---------------------------------------------------------------Threads------------------------------------------------
# Create threads
receivingThreadA = threading.Thread(target=ReceiveThread, args=[1, 'A', socketReceiveA, BUFFER, queue, publicKey, privateKey, sessionKey])
GUIThreadA = threading.Thread(target=GuiThread, args=[2, 'A', socketSendA, BUFFER, queue, publicKey, privateKey, otherPublicKey, sessionKey])

# Start threads
receivingThreadA.start()
GUIThreadA.start()
