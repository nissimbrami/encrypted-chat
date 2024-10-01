import socket
import threading
import time
from tkinter import *
from tkinter import messagebox
import pickle
import rsa
import binascii
import random

name =  input("enter your name: ")
public ,  private = rsa.generate_keypair(1024)
msg =  pickle.dumps(public)
client = None
root =   None
chat_frame  = None
canvas  = None
message_entry =  None
security_level =  None


def set_ip(event=None) :
    ip =  ip_entry.get()
    port =  port_entry.get()

    global  client
    client =  socket.socket()
    client.connect ((ip, int(port)))

    setup_window.destroy ()

    auth_response  = client.recv(1024).decode()
    if auth_response  == "ACCEPTED":
        start_chat ()
    else :
        messagebox.showerror ("the server rejected your request", "The server rejected your connection.")
        client.close()
        exit()


def start_chat():
    global name1 , pkey
    name1 =   client.recv(1024).decode()
    client.send(str.encode(name))
    rmsg =   client.recv(1024)
    pkey =  pickle.loads(rmsg)
    client.send(msg)

    create_main_chat_gui()


def send(event=None):
    if str(message_entry.get()).strip() != "":
        message   = str.encode(message_entry.get())
        hex_data  = binascii.hexlify(message)
        plain_text  = int(hex_data, 16)
        ctt =  rsa.encrypt(plain_text, pkey)
        client.send(str(ctt).encode())
        display_message("You", message_entry.get(), True)
        message_entry.delete(0, END)
        update_security_level()


def recieve()  :
    while True :
        response_message   =   int(client.recv(1024).decode())
        decrypted_msg =   rsa.decrypt(response_message,  private)
        display_message(name1 , str(decrypted_msg),  False)
        update_security_level()


def display_message(sender,   message, is_self):
    frame =   Frame(chat_frame, bg="#34495E")
    frame.pack(fill=X,  padx=10,  pady=5)

    emoji  = random.choice(["😎", "🕵️", "🔐", "🛡️", "🔒", "🤖"])
    sender_label =  Label(frame, text=f"{emoji} {sender}:", font=("Arial", 10, "bold"), bg="#34495E", fg="#ECF0F1")
    sender_label.pack(side=LEFT, padx=(0, 5))

    message_bg =  "#2ECC71" if is_self else "#3498DB"
    message_label  = Label(frame,  text=message,  wraplength=500,  justify=LEFT,  bg=message_bg,  fg="#ECF0F1", padx=5,
                          pady=5)
    message_label.pack(side=LEFT  if is_self else RIGHT, fill=X, expand=True)

    chat_frame.update_idletasks()
    canvas.config(scrollregion=canvas.bbox("all"))
    canvas.yview_moveto(1)


def update_security_level():
    levels =  ["SUPER SECURE! 🚀",  "FORT KNOX LEVEL! 🏰",  "AREA 51 CLEARANCE! 👽",  "LIZARD PEOPLE PROOF! 🦎"]
    security_level.config(text=f"Security Level:  {random.choice(levels)}")


def create_main_chat_gui():
    global root, chat_frame, canvas, message_entry, security_level
    root  = Tk()
    root.title(f"🔒 Super Secret Chat Client - {name}")
    root.geometry("600x700")
    root.configure(bg="#2C3E50")

    # Top frame for encryption visualization
    top_frame  = Frame(root, bg="#2C3E50")
    top_frame.pack(fill=X, padx=10, pady=10)

    encryption_label =  Label(top_frame, text="🔐 Quantum Encryption Active", font=("Arial", 14, "bold"), bg="#2C3E50",
                             fg="#E74C3C")
    encryption_label.pack(side=LEFT)

    security_level =  Label(top_frame, text="Security Level: AREA 51 CLEARANCE! 👽", font=("Arial", 12), bg="#2C3E50",
                           fg="#ECF0F1")
    security_level.pack(side=RIGHT)

    # Chat frame (80% of the remaining space)
    chat_container =  Frame(root, bg="#34495E")
    chat_container.pack(fill=BOTH, expand=True, padx=10, pady=(0, 10))

    canvas =  Canvas(chat_container, bg="#34495E")
    scrollbar =  Scrollbar(chat_container, orient=VERTICAL, command=canvas.yview)
    chat_frame =  Frame(canvas, bg="#34495E")

    canvas.pack(side=LEFT,  fill=BOTH, expand=True)
    scrollbar.pack(side=RIGHT,  fill=Y)

    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.bind('<Configure>',  lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

    canvas.create_window((0, 0),  window=chat_frame, anchor="nw", width=580)

    # Input frame (20% of the remaining space)
    input_frame = Frame(root,  bg="#34495E",  height=140)  # Approximately 20% of 700px
    input_frame.pack(fill=X, padx=10,  pady=10)
    input_frame.pack_propagate(False)

    lock_icon = Label(input_frame,  text="🔒", font=("Arial", 24), bg="#34495E", fg="#E74C3C")
    lock_icon.pack(side=LEFT,  padx=(0, 5))

    message_entry = Entry(input_frame,  bg="#ECF0F1", fg="#2C3E50", font=("Arial", 12), relief=FLAT)
    message_entry.pack(side=LEFT,  expand=True, fill=BOTH, pady=5)

    send_btn =  Button(input_frame,  text="📤 Transmit", command=send, bg="#E74C3C", fg="#ECF0F1",
                      activebackground= "#C0392B",   font= ("Arial", 12, "bold"), relief=FLAT)
    send_btn.pack(side=RIGHT, padx=(5, 0), ipadx=10, ipady = 5)

    root.bind('<Return>', send)

    threading.Thread(target=recieve, daemon=True).start()

    root.mainloop()


# Client Setup GUI
setup_window = Tk()
setup_window.title("🔒 Top Secret Chat Client Setup")
setup_window.geometry("400x300")
setup_window.configure(bg="#2C3E50")

setup_frame = Frame(setup_window, bg="#34495E", padx=20, pady=20)
setup_frame.pack(expand=True, fill=BOTH)

Label(setup_frame, text="🕵️ Ultra Secure Chat Client", font=("Arial", 16, "bold"), bg="#34495E", fg="#ECF0F1").pack(
    pady=10)

ip_label = Label(setup_frame, text="🌐 Enter Secret Server IP:", bg="#34495E", fg="#ECF0F1", font=("Arial", 12))
ip_label.pack(fill=X)
ip_entry = Entry(setup_frame, font=("Arial", 12), bg="#ECF0F1")
ip_entry.pack(fill=X, pady=5)

port_label = Label(setup_frame, text="🔌 Enter Covert Port:", bg="#34495E", fg="#ECF0F1", font=("Arial", 12))
port_label.pack(fill=X)
port_entry = Entry(setup_frame, font=("Arial", 12), bg="#ECF0F1")
port_entry.pack(fill=X, pady=5)

connect_btn = Button(setup_frame, text="🚀 Establish Secure Connection", command=set_ip, bg="#E74C3C", fg="#ECF0F1",
                     activebackground="#C0392B", font=("Arial", 12, "bold"))
connect_btn.pack(fill=X, pady=10)

setup_window.bind('<Return>', set_ip)

setup_window.mainloop()

##this is the last version that workoing with approvment clients