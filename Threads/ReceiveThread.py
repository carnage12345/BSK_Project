import time
import os
from RSAKeysLibrary import *


def ReceiveThread(threadID, name, socket, BUFFER, queue, publicKey, privateKey, sessionKey):

    #  MAIN LOOP
    while True:
        #TEST = socket.recv(BUFFER).decode("utf8")
        TEST = decrypt(socket.recv(BUFFER), privateKey)


        print("TEST:" + TEST)
        if TEST == "message":
            socket.send("OK".encode())

            msg = socket.recv(BUFFER).decode()
            queue.put('You received a message:\n' + msg)
            socket.send("FINISHED".encode())


        if TEST == "file":
            socket.send("OK".encode())

            SEPARATOR = "<SEPARATOR>"
            received = socket.recv(BUFFER).decode()
            filePath, fileSize = received.split(SEPARATOR)

            fileName = os.path.basename(filePath)
            fileSize = int(fileSize)  # fileSize in bytes

            # progress
            with open("./AcquiredFiles" + name + "/" + fileName, "wb") as f:
                receivedDataSize = 0

                startTime = time.time()

                while receivedDataSize < int(fileSize):
                    data = socket.recv(BUFFER)
                    if not data:
                        break  # no data means that full file has been received
                    f.write(data)
                    receivedDataSize += len(data)

                endTime = time.time()

                queue.put('You received a file:\nName: ' + fileName + '\nPath: ' + str(os.getcwd()) +
                          '\\AcquiredFiles' + name + "\\" + fileName + '\nSize: ' + str(fileSize / 1048576) +
                          ' MB\nTransfer time: ' + str(endTime - startTime) + ' s')
            socket.send("FINISHED".encode())


        if TEST == "file_encoded_cbc":
            socket.send("OK".encode())

            iVectorCBC = socket.recv(16)
            cipherCBC = AES.new(sessionKey, AES.MODE_CBC, iVectorCBC)

            SEPARATOR = "<SEPARATOR>"
            received = socket.recv(BUFFER).decode()
            filePath, fileSize = received.split(SEPARATOR)

            fileName = os.path.basename(filePath)
            fileSize = int(fileSize)  # fileSize in bytes

            # progress
            with open("./AcquiredFiles" + name + "/" + fileName, "wb") as f:
                receivedDataSize = 0

                startTime = time.time()

                while receivedDataSize < int(fileSize):
                    data = unpad(cipherCBC.decrypt(socket.recv(BUFFER)), AES.block_size)
                    if not data:
                        break  # no data means that full file has been received
                    f.write(data)
                    receivedDataSize += len(data)

                endTime = time.time()

                queue.put('You received a file:\nName: ' + fileName + '\nPath: ' + str(os.getcwd()) +
                          '\\AcquiredFiles' + name + "\\" + fileName + '\nSize: ' + str(fileSize / 1048576) +
                          ' MB\nTransfer time: ' + str(endTime - startTime) + ' s')
            socket.send("FINISHED".encode())

        if TEST == "file_encoded_ecb":
            socket.send("OK".encode())

            cipherECB = AES.new(sessionKey, AES.MODE_ECB)

            SEPARATOR = "<SEPARATOR>"
            received = socket.recv(BUFFER).decode()
            filePath, fileSize = received.split(SEPARATOR)

            fileName = os.path.basename(filePath)
            fileSize = int(fileSize)  # fileSize in bytes

            # progress
            with open("./AcquiredFiles" + name + "/" + fileName, "wb") as f:
                receivedDataSize = 0

                startTime = time.time()

                while receivedDataSize < int(fileSize):
                    data = unpad(cipherECB.decrypt(socket.recv(BUFFER)), AES.block_size)
                    if not data:
                        break  # no data means that full file has been received
                    f.write(data)
                    receivedDataSize += len(data)

                endTime = time.time()

                queue.put('You received a file:\nName: ' + fileName + '\nPath: ' + str(os.getcwd()) +
                          '\\AcquiredFiles' + name + "\\" + fileName + '\nSize: ' + str(fileSize / 1048576) +
                          ' MB\nTransfer time: ' + str(endTime - startTime) + ' s')
            socket.send("FINISHED".encode())



        if TEST == "message_encoded":
            socket.send("OK".encode())

            print("we received a secret message from our spies my lord...")
            messageEncoded = socket.recv(BUFFER)
            print("message encrypted:")
            print(messageEncoded)
            print("message decrypted:")
            messageDecoded = decrypt(messageEncoded, privateKey)
            print(messageDecoded)
            queue.put("You received message encrypted with RSA:" + str(messageDecoded))

            socket.send("FINISHED".encode())

        if TEST == "message_encoded_cbc":
            socket.send("OK".encode())

            print("CBC message has entered the castle")
            iVectorCBC = socket.recv(16)
            print("vector:" + str(iVectorCBC))
            print("koniec wektora")

            ciphertext = socket.recv(BUFFER)
            print("message encrypted:")
            print(ciphertext)
            print("message decrypted:")
            cipher = AES.new(sessionKey, AES.MODE_CBC, iVectorCBC)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode("utf-8") # JESZCZE DECODE TRZEBA DODAC
            print(plaintext)
            queue.put("Message encoded with CBC with session key:" + str(plaintext))

            socket.send("FINISHED".encode())

        if TEST == "message_encoded_ecb":
            socket.send("OK".encode())

            print("ECB message has entered the castle")
            ciphertext = socket.recv(BUFFER)
            print("message encrypted:")
            print(ciphertext)
            print("message decrypted:")
            cipher = AES.new(sessionKey, AES.MODE_ECB)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode("utf-8")
            print(plaintext)
            queue.put("Message encoded with ECB with session key:" + str(plaintext))

            socket.sendall("FINISHED".encode())
