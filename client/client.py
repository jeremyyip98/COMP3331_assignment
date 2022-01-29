############################################
# UNSW 2020 Term 3 COMP3331 Assignment
# Written by Yip Jeremy Chung Lum, z5098112
# Python 3.7
# Usage: python3 client.py localhost 12000
# coding: utf-8
############################################
from os import path
from socket import *
import atexit
import base64
import json
import sys
import threading
import time


# Check the number of command line arguments
if len(sys.argv) != 3:
    print("Usage: python3 client.py server_IP server_port")
    exit(0)
server_IP = sys.argv[1]
server_port = int(sys.argv[2])

# Connect to the server
clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((server_IP, server_port))

username = ""
thread_title = ""
filename = ""
file_content = b""

recv = False
to_exit = False

buffer_size = 1024

def disconnect():
    print("\rGoodbye")

    clientSocket.close()

# start the interaction between client and server
def interact():
    recv_thread = threading.Thread(name="RecvHandler", target=recv_handler)
    recv_thread.daemon = True
    recv_thread.start()

    send_thread = threading.Thread(name="SendHandler", target=send_handler)
    send_thread.daemon = True
    send_thread.start()


    while True:
        time.sleep(0.1)

        # when set true, exit the main thread
        if to_exit:
            clientSocket.close()
            exit(0)

# Helper function to change the buffer size to a correct number of bytes in order to recv incoming file
def change_buffer(file_size):
    global buffer_size
    result = 1024
    # Only stop when the result is greater than the file length
    while file_size >= result:
        result = result * 2
    buffer_size = result

# Helper function to interact with the server based on the input command
# it keeps on looping until it gets a correct command
def send_handler():
    global thread_title
    global filename
    global file_content
    global recv
    while True:
        if recv:
            recv = False
            message = input('Enter one of the following commands: CRT, MSG, DLT, EDT, LST, RDT, UPD, DWN, RMV, XIT, SHT: ')
            while not message:
                print('Arguments cannot be empty\n')
                message = input('Enter one of the following commands: CRT, MSG, DLT, EDT, LST, RDT, UPD, DWN, RMV, XIT, SHT: ')
            command_list = message.split()
            command = command_list[0]
            length = len(command_list)

            if command == "CRT":
                if length != 2:
                    print('Invalid number of arguments\n')
                    print("Usage: CRT threadtitle\n")
                    recv = True
                else:
                    thread_title = command_list[1]
                    clientSocket.send(json.dumps({
                        "action": "Command",
                        "status": command,
                        "username": username,
                        "thread_title": thread_title
                    }).encode('utf-8'))
            elif command == "MSG":
                if length < 3:
                    print('Invalid number of arguments\n')
                    print("Usage: MSG threadtitle message\n")
                    recv = True
                else:
                    thread_title = command_list[1]
                    message = command_list[2]
                    # Looping through the list start at the fourth element
                    for msg in command_list[3:]:
                        message = message + ' ' + msg
                    clientSocket.send(json.dumps({
                        "action": "Command",
                        "status": command,
                        "username": username,
                        "thread_title": thread_title,
                        "message": message
                    }).encode('utf-8'))
            elif command == "LST":
                if length != 1:
                    print('Invalid number of arguments\n')
                    print("Usage: LST\n")
                    recv = True
                else:
                    clientSocket.send(json.dumps({
                        "action": "Command",
                        "status": command
                    }).encode('utf-8'))
                    result = True
            elif command == "RDT":
                if length != 2:
                    print('Invalid number of arguments\n')
                    print("Usage: RDT threadtitle\n")
                    recv = True
                else:
                    thread_title = command_list[1]
                    clientSocket.send(json.dumps({
                        "action": "Command",
                        "status": command,
                        "thread_title": thread_title
                    }).encode('utf-8'))
            elif command == "DLT":
                if length != 3:
                    print('Invalid number of arguments\n')
                    print("Usage: DLT threadtitle messagenumber\n")
                    recv = True
                elif not command_list[2].isnumeric():
                    print('Message number can only contain numbers\n')
                    print("Usage: DLT threadtitle messagenumber\n")
                    recv = True
                else:
                    thread_title = command_list[1]
                    msg_num = command_list[2]
                    clientSocket.send(json.dumps({
                        "action": "Command",
                        "status": command,
                        "username": username,
                        "thread_title": thread_title,
                        "message_number": msg_num
                    }).encode('utf-8'))
            elif command == "EDT":
                if length < 4:
                    print('Invalid number of arguments\n')
                    print("Usage: EDT threadtitle messagenumber message\n")
                    recv = True
                elif not command_list[2].isnumeric():
                    print('Message number can only contain numbers\n')
                    print("Usage: EDT threadtitle messagenumber message\n")
                    recv = True
                else:
                    thread_title = command_list[1]
                    msg_num = command_list[2]
                    message = command_list[3]
                    # Looping through the list start at the fifth element
                    for msg in command_list[4:]:
                        message = message + ' ' + msg
                    clientSocket.send(json.dumps({
                        "action": "Command",
                        "status": command,
                        "username": username,
                        "thread_title": thread_title,
                        "message_number": msg_num,
                        "message": message
                    }).encode('utf-8'))
            elif command == "RMV":
                if length != 2:
                    print('Invalid number of arguments\n')
                    print("Usage: RMV threadtitle\n")
                    recv = True
                else:
                    thread_title = command_list[1]
                    clientSocket.send(json.dumps({
                        "action": "Command",
                        "status": command,
                        "username": username,
                        "thread_title": thread_title
                    }).encode('utf-8'))
            elif command == "UPD":
                if length != 3:
                    print('Invalid number of arguments\n')
                    print("Usage: UPD threadtitle filename\n")
                    recv = True
                else:
                    thread_title = command_list[1]
                    filename = command_list[2]
                    if not path.exists("{}".format(filename)):
                        print('File {} does not exist\n'.format(filename))
                        recv = True
                    else:
                        f = open("{}".format(filename),"rb")
                        file_content = f.read()
                        f.close()
                        clientSocket.send(json.dumps({
                            "action": "Command",
                            "status": command,
                            "thread_title": thread_title,
                            "file_size": len(file_content)
                        }).encode('utf-8'))
            elif command == "DWN":
                if length != 3:
                    print('Invalid number of arguments\n')
                    print("Usage: DWN threadtitle filename\n")
                    recv = True
                else:
                    thread_title = command_list[1]
                    filename = command_list[2]
                    clientSocket.send(json.dumps({
                        "action": "Command",
                        "status": command,
                        "thread_title": thread_title,
                        "filename": filename
                    }).encode('utf-8'))
            elif command == "XIT":
                if length != 1:
                    print('Invalid number of arguments\n')
                    print("Usage: XIT\n")
                    recv = True
                else:
                    clientSocket.send(json.dumps({
                        "action": "Command",
                        "status": command
                    }).encode('utf-8'))
            elif command == "SHT":
                if length != 2:
                    print('Invalid number of arguments\n')
                    print("Usage: SHT admin_password\n")
                    recv = True
                else:
                    admin_password = command_list[1]
                    clientSocket.send(json.dumps({
                        "action": "Command",
                        "status": command,
                        "admin_password": admin_password
                    }).encode('utf-8'))
            else:
                print('Invalid command')
                recv = True


# handles all incoming data and selectively display useful information to user
def recv_handler():
    global buffer_size
    global username
    global recv
    global to_exit
    while True:
        login_result = clientSocket.recv(buffer_size)
        data = json.loads(login_result.decode('utf-8'))
        if data['action'] == 'Login':
            if data['status'] == 'USER_EXIST':
                password = input("Enter password: ")

                # send password to server
                clientSocket.send(json.dumps({
                    "action": "Login",
                    "status": "SENDING_PASSWORD",
                    "username": username,
                    "password": password
                }).encode('utf-8'))
            elif data['status'] == "USER_LOGGED_IN":
                print('{} has already logged in\n'.format(username))
                username = input("Enter username: ")

                # send username to server
                clientSocket.send(json.dumps({
                    "action": "Login",
                    "status": "SENDING_USERNAME",
                    "username": username
                }).encode('utf-8'))
            elif data['status'] == 'NEW_USER':
                password = input("Enter new password for {}: ".format(username))

                # send password to server
                clientSocket.send(json.dumps({
                    "action": "Login",
                    "status": "ADDING_NEW_PASSWORD",
                    "username": username,
                    "password": password
                }).encode('utf-8'))
            elif data['status'] == 'INVALID_PASSWORD':
                print('Invalid password\n')
                username = input("Enter username: ")

                # send username to server
                clientSocket.send(json.dumps({
                    "action": "Login",
                    "status": "SENDING_USERNAME",
                    "username": username
                }).encode('utf-8'))
            elif data['status'] == 'SUCCESSFUL_LOGIN':
                print('Welcome to the forum\n')
                recv = True
        elif data['action'] == 'Command':
            if data['status'] == 'THREAD_EXIST':
                print('Thread {} exists\n'.format(thread_title))
                recv = True
            elif data['status'] == 'THREAD_CREATED':
                print('Thread {} created\n'.format(thread_title))
                recv = True
            elif data['status'] == 'POST_SUCCEES':
                print('Message posted to {} thread\n'.format(thread_title))
                recv = True
            elif data['status'] == 'THREAD_NOT_EXIST':
                print('Thread {} does not exist\n'.format(thread_title))
                recv = True
            elif data['status'] == 'THREAD_ACTIVE':
                thread_list = data['threads']

                print('The list of active threads:\n')
                for thread in thread_list:
                    print(thread + '\n')
                recv = True
            elif data['status'] == 'THREAD_INACTIVE':
                print('No threads to list\n')
                recv = True
            elif data['status'] == "READ_SUCCEES":
                content = data['thread_content']
                # If the content is not empty
                if content:
                    for line in content:
                        print(line)
                else:
                    print('Thread {} is empty\n'.format(thread_title))
                recv = True
            elif data['status'] == 'INVALID_MSG_NUM':
                print('Invalid message number\n')
                recv = True
            elif data['status'] == 'INVALID_USER':
                print('The message belongs to another user and cannot be edited\n')
                recv = True
            elif data['status'] == "THREAD_IS_FILE":
                print('File cannot be edtied\n')
                recv = True
            elif data['status'] == 'THREAD_EMPTY':
                print('Thread {} is empty\n'.format(thread_title))
                recv = True
            elif data['status'] == 'MSG_DELETED':
                print('The message has been deleted\n')
                recv = True
            elif data['status'] == 'MSG_EDITED':
                print('The message has been edited\n')
                recv = True
            elif data['status'] == 'INVALID_THREAD_CREATOR':
                print('The thread was created by another user and cannot be removed\n')
                recv = True
            elif data['status'] == 'THREAD_REMOVED':
                print('The thread has been removed\n')
                recv = True
            elif data['status'] == "UPD_THREAD_EXIST":
                clientSocket.send(json.dumps({
                "action": "Command",
                "status": "UPD_FILE",
                "username": username,
                "thread_title": thread_title,
                "filename": filename,
                "file_content": base64.b64encode(file_content).decode("ascii")
                }).encode('utf-8'))
            elif data['status'] == "UPLOAD_SUCCESS":
                print('{} uploaded to {} thread\n'.format(filename, thread_title))
                recv = True
            elif data['status'] == "FILE_NOT_EXIST":
                print('File does not exist in Thread {}\n'.format(thread_title))
                recv = True
            elif data['status'] == "INCOMING_FILE_SIZE":
                change_buffer(data['file_size'])
            elif data['status'] == "DOWNLOAD_SUCCESS":
                # Reset the buffer size
                buffer_size = 1024
                dwn_file = base64.b64decode(data['file_content'])
                # Based on the given assumption in the spec,  that a file with this same name 
                # does not exist in the current working directory of the client.
                # Hence, do not need to check the existance a same filename in the current directory.
                f = open("{}".format(filename),"wb")
                f.write(dwn_file)
                f.close()

                print('{} successfully downloaded\n'.format(filename))
                recv = True
            elif data['status'] == "CONNECTION_END":
                print('Goodbye\n')
                to_exit = True
                exit(0)
            elif data['status'] == "INCORRECT_PASSWORD":
                print("Incorrect password\n")
                recv = True
        elif data['action'] == 'Shutdown':
            print('\nGoodbye, server shutting down\n')
            to_exit = True
            exit(0)

# The main function
def connect():
    global username
    message = {
        "action": "Login",
        "status": "CONNECTING"
    }
                    
    clientSocket.send(json.dumps(message).encode('utf-8'))

    # wait for the reply from the server
    login_result = clientSocket.recv(buffer_size)
    login_result = json.loads(login_result.decode('utf-8'))

    if login_result["action"] == "Login" and login_result["status"] == "CONNECTED":
        # successfully authenticated
        print("You have successfully setup a connection with the server\n")

        username = input("Enter username: ")

        # send username to server
        clientSocket.send(json.dumps({
            "action": "Login",
            "status": "SENDING_USERNAME",
            "username": username
        }).encode('utf-8'))

        # start interaction
        interact()

    # Close the socket

if __name__ == "__main__":
    # start to authenticate user
    connect()