# <center>SHELL STATION</center>


# Description

Shellstation is a C2 (command and control) tool for managing malware sessions. First off, this does not give any clue about how to write a malware, it only acts as a listener with many functionalities. The main use of shellstation is to handle shell sessions from multiple victims even if they come at the same time and be able to switch between those sessions easily. The most powerful side of this tool is that it can operate in two different modes: cli mode and server mode.

# Dependencies
This tool is meant to run on a linux system and it depends on the python library pycryptodome to run smoothly. Please make sure you install that library with the following command:
> pip install pycryptodome<BR>
  
OR<BR>

> pip3 install pycrpytodome<BR>

It should also be noted that shellstation is coded in python3.

# Server mode

Server mode is the mode where the tool can be placed in a public server to listen for connections 24/7. When started in server mode the program binds to two local ports. One of them is for authentication where a client will connect to the server to manage the shell sessions after supplying the credentials and the other is to deploy the listener that our malware will connect back to. In order to start the program in server mode, two command line options need to be supplied: -p and -l. The -p option specifies the port where authentication by the client will be handled and the -l option tells shellstation which port to deploy the listener on.
> python3 shellstation.py -p 1234 -l 80 (enter the server mode)

NOTE: All the commands explained in server mode section can be run after a successful authentication to the server

## How to register a client
We previously taked about authentication. Before authentication can take place, there needs to be some clients already registered in our server. In order to register a client, the program should be started in CLI mode (explained below) and register command needs to be run. The rest of this process is straightforward. The program asks for a username, password and the role of the client. After registering the client, a file called database will be created where the username, sha256 hash of the password and the role of the client is present. As more clients are added, new lines get written to the file. Aside from doing this in cli mode, it can also be done through an admin user after a successful authentication. However if it's your first time and you dont have any users, you should create the user using cli mode.
> register john mystrongpass a (server mode) <BR>
> register (cli mode, interactive)

## How to connect to the server
The script named "client.py" peforms authentication to the server. This script takes two positional command line arugments with the first one being the server IP and the second one being the port for authentication (specified by -p when starting the program in server mode). It asks for a username and a password. When user enters the credentials, they go to the server in an encrypted way and get decrypted on the server side. The server takes the sha256 hash of the password and compares it to the saved hash in the database. If the username and passwords match, the client gets authenticated successfully.
> python3 client.py 127.0.0.1 1234

## Roles
We talked about roles when registering users. Roles specify how privileged a user is. If the user is the admin denoted by a, they can carry out administrative actions like removing users, killing shell sessions, executing any commands, listing and deauthenticating users. Admin can do all these things by authenticating to the server using client.py which eliminates the need of entering the CLI mode. Another role that's defined in the server is regular user dnoted by r which allows the users to only execute commands other than the ones that contain kill, exit or any command substitution characters to prevent them from being able to kill the shell sessions. The reason for that is killing a session is an administrative task and can only be performed by an admin user. What regular user can additionally do are simple actions like listing shell sessions and swithcing between them. Our last role is guest denoted by d. The guest user basically cannot do anything but to list out shell sessions. That user is the lowest privileged user and should only be in the system to check if we popped any shells. If you're in an environment where you need to work with people that are not really trusted, guest user is the best role for them.
> a = admin<BR>
> r = regular user<BR>
> g = guest

## Encryption
The entire communication, including the authentication request, between the client and the shellstation server is encrypted. When connecting to the server, the server shares a public RSA encryption key we are using to encrypt an AES symmetric key. The use of assymetric encyption to send a symmetric encryption key ensures a fast and secure way of encrypting the traffic and simulates a PGP like protocol. After the AES key has securely been transmitted to the server, both the client and the server starts using that key in order to communicate with each other. Thus, no plain text data is sent between client and the server. However, that doesnt ensure any encryption between our server and the malware agent. If you want to encrypt that traffic as well, the encryption code should be implemented when writing the malware.

## Logging
Most of the operations performed by the clients get logged into the terminal screen as well as being written to a log file named "log". The format of the logs is a timestamp followed by the log information. Log file only gets created in server mode

## Keepalive
If we dont send any command to the victim and the connection between the server and the malware agent stays idle for more than 120 senconds, the shellstation server sends some keepalive data every 120 seconds to the malware agent to keep the session alive. This is especially useful in some environments where the firewall might be terminating connections if they stay idle for too long.

## Registering in server mode
As mentioned above administrator users can register clients without needing to enter cli mode. While registering the users, the following systax has to be used: register username password role. (Example: register admin admin a). The role can either be a, r or g (a=admin, r=regular user, g=guest).
> register alice p4ssw0rd r<BR>
> register guesuser guestpass g

## Listing and deauthenticating connected clients
Admin users can list out what clients are connected and deauthenicate them very easily. The command "clients" is used to display all the connected clients. If one client needs to be deauthenicated, the command "deauth client_name" is used.
> clients (get a list of clients)<BR>
> deauth john (disconnect john)

## Removing clients
If a client should no longer be able to authenticate to the server, only the admin user can remove it. The syntax to remove a client is as follows: remove client_name. This usage of the command is the same for both server and cli mode.
> remove john

## Listing all the active sessions
In order to get a listing for what sessions are available, type the command "sessions". It displays all the active sessions. The format of the output contains a session id followed by the IP address and the port of the connecting client
> sessions

## Interacting with the sessions
After getting a listing for the active sessions and their IDs, we can use "interact session_id" command to interact with a session. After running this command we can execute commands on the victim's system.
> interact 5

## Confirm, disconfirm and kill
In real life situations, scanners and other automated tools might possibly connect to the listen port of the shellstation server which will be displayed as an active session when you run the sessions command. When you run confirm along with a sessio ID (confirm 4), a green plus sign get printed right next to the specified session every time you run sessions command. That allows users to mark the real sessions and differentiate them from the scanner's connections. The connections established by scanners wont be responsive anyways. The can manually be detected easily and killed using the kill command. The kill command must be given a session id to kill. Also, in order to undo a confirm operation, disconfirm should be used with the session ID in the same manner.
> confirm 4<BR>
> disconfirm 4<BR>
> kill 5

## Exitting
In order to disconnect from the server and exit out of the client.py program, run exit.
> exit

# CLI Mode
CLI is the mode where all the sessions can be managed from the command line interface. If the program is run without supplying any options, it will run in CLI mode. There are specific commands we can run to manage our sesssions which are listed below.
> python3 shellstation.py (enter the cli mode)

## Listening for incoming sessions
The command "listen" is used for binding to a local port for incoming connections. The syntax is the command "listen" followed by the port to listen on. There's also the "-b" switch that can be used in conjunction with listen to start the listener in the background so that more than one incoming session can be caught at a time.

Sample Usage:
> listen 4444<BR>
> listen -b 4444<BR>

## Stopping background listeners
If one or more listener threads are running in the background, there's a way to stop them all at once. The "stop" command with no arguments will stop any background listener threads that might be running regardless of how many of them there are.

Sample Usage:
> stop

## Displaying and switching between active sessions
The command "sessions" is used to list out all the active sessions caught by our handler along with their session ids. These sessions are a bunch of socket handles stored in a global dictionary variable. In order to interact with one of them, type in the "interact" command followed by the session id. That allows you to drop into the specified shell session.

Sample Usage:
> sessions<BR>
> interact 3<BR>

If you want to leave the current session you are in without shutting it down permanently, press Ctrl + C and it will only terminate the handler threads, not the socket handle itself. That way, you get back to the main program prompt without terminating that particular session. From that point on, you can switch over to any other session you want

## Understanding, displaying, and loading modules
When you type in the command "modules", you'll get a list of handler modules available on the framework. No matter what you have in your modules folder, the "default" module should always be there (Don't ever delete the modules folder. Otherwise the program won't run). What the default handler module does is take any input supplied from the terminal and forward it to the target shell. "background" and "bg" are the only two commands that are exceptions. They put the session in the background and bring you back to the main prompt. (For most users, the default handlers will be enough. There's mostly no need for external handler modules)

Sample Usage:
> modules<BR>

In order to use a module, type in the command "use" along with the module id that's displayed in the output of the "modules" command or follow the "use" command by the module name (Type in the name you see in the output of modules command which doesn't contain .py extension). Then you should see the module name in blue parenthesis right next to the main prompt.

Sample Usage:
> use 1<BR>
> use default<BR>

In the modules folder, we can include external handler modules that can be imported to our main script. The reason for including modules is that you may sometimes want to perform different actions based on the input supplied from the attacker's terminal. In these cases, the default handler module won't be enough since it only forwards whatever's given to it to the victim. Before you start to write your own handlers, keep in mind that the "socket" library should always be imported along with defining send_data(conn, st) and receive_data(conn, st) functions. These definitions are necessary for the module to work properly. (An example module is provided in the modules folder with the name example_modules.py)

Both send_data and receive_data functions should take exactly two arguments. The first one is conn as seen above which is the socket handle that will be used to communicate with the target session. The second argument is st (short for stop). This is a global object with one property which is stop. Stop is a boolean variable that's been used in handler.py to manage when to terminate the "receive_data" thread. The way it's used is whenever "bg", "background", or Ctrl+C is detected, this global value is set to True. At the same time, the "receive_data" thread checks this value every half a second and if st.stop evaluates to True, it terminates the thread. That way you successfully get back to the main prompt again. (Again, most of the time you don't need to deal with these things. The default handler is enough for most users but the framework enables you to write your own customized handlers)

## Killing sessions
Kill can be used in one of two ways:

> kill all<BR>
> kill 3<BR>

As you may have guessed, "kill all" kills all the sessions by sending "exit" command to the shell session and unloading it's socket handle from the memory. "kill 3" kills the session with id 3 the same way.

## Clearing the screen
Most of the time, it's a habit of a Linux user to clear the screen pretty often. But if you have an important piece of data you received from the shell session and accidentally clear it out, that would be a little problematic. That's why every time you type in the "clear" command, the program asks you if you really want to clear the screen out. If you type in "y", only then the screen gets cleared.

## Exiting the program
Ctrl+C or EOF cannot be used to terminate the program. It's very easy to accidentally press Ctrl+C or Ctrl+D and terminate all the sessions you have on your target. Because of that, the only way to exit out of this program is to manually type exit. Then the program will be terminated along with any possible active shell you might have.

## Getting help
The "help" command displays a basic help screen with available commands. "help" followed by the command name will display a more detailed help screen for that specific command.

## Thread Count
Every time we attach to a session or start a listener that binds to a local port, we create a thread. And the "threads" command displays the number of threads that are running in the program. At the very beginning, it will be 1. That is a debugging feature coded for developers to check if there are any unterminated threads where there should be none.


