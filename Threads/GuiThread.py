import tkinter as tk
from tkinter import ttk
from tkinter import OptionMenu
from RSAKeysLibrary import *
from tkinterLibrary import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def GuiThread(threadID, name, socket, BUFFER, queue, publicKey, privateKey, otherPublicKey, sessionKey):

    #  -------
    #  TKINTER
    #  -------
    window = tk.Tk()
    window.title('Client ' + name)
    window.geometry('500x600')


    #  ---------------------
    #  GLOBALS FOR TKINTER #
    #  ---------------------
    pathStringVar = tk.StringVar()
    pathStringVar.set("path to the file we are sending")
    #  ---------------------


    #  --------------------
    #  TKINTER MAIN PROGRAM
    #  --------------------
    tk.Label(window, text='BSK Project').pack()
   # tk.Label(window, text='Message:').pack()

    # entry = tk.Entry(window)
    # entry.pack()
    #
    # sendButton = tk.Button(window, text='send message', command=lambda: button_send_message(BUFFER, entry, socket, otherPublicKey))
    # sendButton.pack()
    #
    #
    # #  RSA Messages (to delete in future) (won't be used for message exchange just session key)
    # entry_encoded_rsa = tk.Entry(window)
    # entry_encoded_rsa.pack()
    #
    # sendButtonEncoded = tk.Button(window, text='send message Encoded RSA', command=lambda: send_message_encoded_rsa(BUFFER, entry_encoded_rsa, socket, otherPublicKey, privateKey))
    # sendButtonEncoded.pack()


    #  Ciphering MODE
    tk.Label(window, text='\nChoose ciphering mode:').pack()

    clicked = tk.StringVar()
    clicked.set("CBC")  # default value
    options = ['ECB', 'CBC']
    OptionMenu(window, clicked, *options).pack()

    #  CBC/ECB MESSAGE SENDING
    entry_CBC = tk.Entry(window)
    entry_CBC.pack()

    tk_sendButtonCBC = tk.Button(window, text='send message Encoded CBC/ECB', command=lambda: send_message_encoded(BUFFER, clicked.get(), entry_CBC, sessionKey, socket, otherPublicKey))
    tk_sendButtonCBC.pack()


    #  ------------------INPUT-USER-FRIENDLY-PASSWORD--------------------
    #tk.Label(window, text='Input your user-friendly password').pack()
    #entryPassword = tk.Entry(window)
    #entryPassword.pack()

    #setPasswordButton = tk.Button(window, text='Set password Button (encrypt RSA keys with new key)', command=lambda: button_set_password(entryPassword, rsaLocalKey))
    #setPasswordButton.pack()


    #  ------------------FILE-SENDING--------------------
    #  PROGRESS BAR
    tk.Label(window, text='Progress Bar:').pack()
    progressBar = ttk.Progressbar(window, orient='horizontal', mode='determinate', length=280)
    progressBar.pack()

    progressBarDescription = ttk.Label(window, text="Current Progress: 0%")
    progressBarDescription.pack()

    #  SENDING FILE
    tk.Label(window, textvariable=pathStringVar).pack()

    fileOpenButton = tk.Button(window, text='file dialog', command=lambda: button_open_file(pathStringVar))
    fileOpenButton.pack()

    fileSendButton = tk.Button(window, text='send file', command=lambda: button_send_file(socket, BUFFER, pathStringVar.get(), progressBar, progressBarDescription, window, otherPublicKey))
    fileSendButton.pack()

    fileSendButtonCBCorECB = tk.Button(window, text='send file CBC/ECB', command=lambda: button_send_file_ecb_or_cbc(clicked.get(), socket, BUFFER, pathStringVar.get(), progressBar, progressBarDescription, window, sessionKey, otherPublicKey))
    fileSendButtonCBCorECB.pack()


    # ------------------RECEIVING MESSAGES------------------
    #  Receiving Messages
    tk.Label(window, text='Received section:').pack()

    receivedContent = tk.StringVar()
    receivedContent.set('nothing')

    tk.Button(window, text='check', command=lambda: check_queue(queue, receivedContent)).pack()
    ttk.Label(window, textvariable=receivedContent).pack()

    #  end of LOOP
    window.mainloop()
