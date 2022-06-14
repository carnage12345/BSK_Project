import tkinter
from tkinter import filedialog
from tkinter.messagebox import showinfo
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from RSAKeysLibrary import *
import os


def button_send_message(BUFFER, entry, client, otherPublicKey):
    message = entry.get()
    print(message)

    messageType = encrypt("message", otherPublicKey)

    client.send(messageType)
    #potwierdznie
    client.recv(BUFFER)
    client.send(message.encode("utf8"))
    client.recv(BUFFER) #FINISHED
    popup_msg("Message Sent and Received", "OK")


def send_message_encoded_rsa(BUFFER, tk_entry_encoded, client, otherPublicKey, privateKey):
    message = tk_entry_encoded.get()
    print(message)

    # TEST
    messageType = encrypt("message_encoded", otherPublicKey)
    # TEST
    cipherTextRSA = encrypt(message, otherPublicKey)
    #cipherTextSignatureRSA = sign_sha1(message, privateKey)

    client.send(messageType)
    client.recv(BUFFER)
    client.send(cipherTextRSA)
    if client.recv(BUFFER).decode() == "FINISHED":
        popup_msg("Message RSA Sent and Received", "OK")


def send_message_encoded_cbc(BUFFER, tk_entry_CBC, sessionKey, client, otherPublicKey):   #  OTHER SIDES SESSION KEY!!! and even better 1 session key for both sides, czemu do jasnej cholery jest pad podany na wejsciu
    message = tk_entry_CBC.get()
    print(message)

    messageType = encrypt("message_encoded_cbc", otherPublicKey)

    cipherCBC = AES.new(sessionKey, AES.MODE_CBC)
    iVectorCBC = cipherCBC.iv
    ciphertextCBC = cipherCBC.encrypt(pad(message.encode("utf8"), AES.block_size))

    print(ciphertextCBC)

    client.send(messageType)
    client.recv(BUFFER)

    client.send(iVectorCBC)  # czy wektor powinien byc zakodowany? -nie, nie powinien
    print("vector wysłany: " + str(iVectorCBC))
    client.send(ciphertextCBC)
    print("ciphertext wysłany: " + str(ciphertextCBC))

    if client.recv(BUFFER).decode() == "FINISHED":
        popup_msg("Message Sent and Received", "OK")


def send_message_encoded_ecb(BUFFER, tk_entry_CBC, sessionKey, client, otherPublicKey):
    message = tk_entry_CBC.get()
    print(message)

    messageType = encrypt("message_encoded_ecb", otherPublicKey)

    cipherECB = AES.new(sessionKey, AES.MODE_ECB)
    ciphertextECB = cipherECB.encrypt(pad(message.encode("utf8"), AES.block_size))
    print(ciphertextECB)

    client.send(messageType)
    client.recv(BUFFER)
    client.send(ciphertextECB)
    print("ciphertext wysłany: " + str(ciphertextECB))

    if client.recv(BUFFER).decode() == "FINISHED":  # FINISHED
        popup_msg("Message Sent and Received", "OK")


def send_message_encoded(BUFFER, mode, tk_entry_CBC, sessionKey, client, otherPublicKey):
    if mode == 'CBC':
        send_message_encoded_cbc(BUFFER, tk_entry_CBC, sessionKey, client, otherPublicKey)
    elif mode == 'ECB':
        send_message_encoded_ecb(BUFFER, tk_entry_CBC, sessionKey, client, otherPublicKey)




def button_open_file(pathStringVar):
    path = filedialog.askopenfilename(title="BSK - which file to open?",
                                      filetypes=(("all files", "*.*"),
                                                 ("txt files", "*.txt"),
                                                 ("png files", "*.png"),
                                                 ("pdf files", "*.pdf"),
                                                 ("avi files", "*.avi"),
                                                 ("jpg files", "*.jpg")))
    print(path)
    pathStringVar.set(path)


def button_send_file(client, BUFFER, path, pb, pbValue, window, otherPublicKey):
    messageType = encrypt("file", otherPublicKey)
    client.send(messageType)

    # POTWIERDZENIE
    client.recv(BUFFER).decode()

    SEPARATOR = "<SEPARATOR>"
    # filePath = file_path_test
    filePath = path
    fileSize = os.path.getsize(filePath)

    client.send(f"{filePath}{SEPARATOR}{fileSize}".encode())

    print(filePath)

    print(str(fileSize), ' B, ', str(fileSize / 1024), ' KB, ', str(fileSize / 1048576), ' MB')
    with open(filePath, "rb") as f:
        sendDataSize = 0
        startTime = time.time()
        while sendDataSize < fileSize:
            data = f.read(BUFFER)
            if not data:
                break
            client.sendall(data)
            sendDataSize += len(data)
            # print(str(sendDataSize * 100 / fileSize) + ' %')
            # progress.update(len(bytes_read))
            # progress_bar(pb, pbValue, sendDataSize, fileSize)

            # Progress Bar
            if pb['value'] < 100:
                pb['value'] = int((sendDataSize * 100) / fileSize)
                pbValue['text'] = f"Current Progress: {pb['value']}%"  # update_progress_label(pb)

            window.update()
        endTime = time.time()
        showinfo(message='The progress completed!')
        pb['value'] = 0
        pbValue['text'] = f"Current Progress: 0%"
        print("File transfer complete:", endTime - startTime, " s")
    if client.recv(BUFFER).decode() == "FINISHED":  # FINISHED
        popup_msg("File Sent and Received", "OK")

def button_send_file_cbc(client, BUFFER, path, pb, pbValue, window, sessionKey, otherPublicKey):
    messageType = encrypt("file_encoded_cbc", otherPublicKey)
    client.send(messageType)

    client.recv(BUFFER).decode()

    cipherCBC = AES.new(sessionKey, AES.MODE_CBC)
    iVectorCBC = cipherCBC.iv

    client.send(cipherCBC.iv)

    SEPARATOR = "<SEPARATOR>"

    filePath = path
    fileSize = os.path.getsize(filePath)
    client.send(f"{filePath}{SEPARATOR}{fileSize}".encode())

    print(filePath)

    with open(filePath, "rb") as f:
        sendDataSize = 0
        startTime = time.time()
        while sendDataSize < fileSize:
            data = f.read(BUFFER)
            if not data:
                break
            client.sendall(cipherCBC.encrypt(pad(data, AES.block_size)))
            sendDataSize += len(data)
            if pb['value'] < 100:
                pb['value'] = int((sendDataSize * 100) / fileSize)
                pbValue['text'] = f"Current Progress: {pb['value']}%"  # update_progress_label(pb)

            window.update()

        endTime = time.time()
        showinfo(message='The progress completed!')
        pb['value'] = 0
        pbValue['text'] = f"Current Progress: 0%"
        print("File transfer complete:", endTime - startTime, " s")
    if client.recv(BUFFER).decode() == "FINISHED":  # FINISHED
        popup_msg("File Sent and Received", "OK")



def button_send_file_ecb(client, BUFFER, path, pb, pbValue, window, sessionKey, otherPublicKey):
    messageType = encrypt("file_encoded_ecb", otherPublicKey)
    client.send(messageType)

    client.recv(BUFFER).decode()

    cipherECB = AES.new(sessionKey, AES.MODE_ECB)

    SEPARATOR = "<SEPARATOR>"

    filePath = path
    fileSize = os.path.getsize(filePath)
    client.send(f"{filePath}{SEPARATOR}{fileSize}".encode())

    print(filePath)

    with open(filePath, "rb") as f:
        sendDataSize = 0
        startTime = time.time()
        while sendDataSize < fileSize:
            data = f.read(BUFFER)
            if not data:
                break
            client.sendall(cipherECB.encrypt(pad(data, AES.block_size)))
            sendDataSize += len(data)
            if pb['value'] < 100:
                pb['value'] = int((sendDataSize * 100) / fileSize)
                pbValue['text'] = f"Current Progress: {pb['value']}%"  # update_progress_label(pb)

            window.update()

        endTime = time.time()
        showinfo(message='The progress completed!')
        pb['value'] = 0
        pbValue['text'] = f"Current Progress: 0%"
        print("File transfer complete:", endTime - startTime, " s")
    if client.recv(BUFFER).decode() == "FINISHED":  # FINISHED
        popup_msg("File Sent and Received", "OK")


def button_send_file_ecb_or_cbc(mode, client, BUFFER, path, pb, pbValue, window, sessionKey, otherPublicKey):
    if mode == 'CBC':
        button_send_file_cbc(client, BUFFER, path, pb, pbValue, window, sessionKey, otherPublicKey)
    elif mode == 'ECB':
        button_send_file_ecb(client, BUFFER, path, pb, pbValue, window, sessionKey, otherPublicKey)




def popup_msg(message, title):
    popup = tkinter.Tk()
    popup.title(title)
    label = tkinter.Label(popup, text=message)
    label.pack(side="top", fill="x", pady=10)
    CloseButton = tkinter.Button(popup, text="Okay", command=popup.destroy)
    CloseButton.pack()
    popup.attributes('-toolwindow', True)
    popup.mainloop()


def password_popup_msg(name):
    global password
    password = ""
    global command
    command = ""

    def getpassword():
        global password
        password = passwordVar.get()  # get password from entry
        popup.destroy()

    def resetpass():
        global command
        command = "reset"
        global password
        password = passwordVar.get()
        popup.destroy()

    popup = tkinter.Tk()
    popup.title("PASSWORD:" + name)
    popup.geometry("300x100")
    label = tkinter.Label(popup, text="PASSWORD:")
    label.pack()
    passwordVar = tkinter.StringVar()
    passEntry = tkinter.Entry(popup, textvariable=passwordVar, show='*')
    passEntry.pack()
    submit = tkinter.Button(popup, text='OK', command=getpassword)
    submit.pack()

    reset = tkinter.Button(popup, text='NEW PASSWORD', command=resetpass)
    reset.pack()

    popup.mainloop()
    print("password:" + password)
    return password, command


def check_queue(queue, control):
    if queue.empty():
        print('queue is empty')
        control.set('nothing')
    else:
        print('queue is not empty')
        control.set(queue.get())


def button_set_password(control, rsaLocalKeyClass):
    newPassword = control.get()
    rsaLocalKeyClass.change_password_and_local_key_and_encrypt_rsa_keys_and_save(newPassword)





