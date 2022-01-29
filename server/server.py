#####################################################
# UNSW 2020 Term 3 COMP3331 Assignment
# Written by Yip Jeremy Chung Lum, z5098112
# Python 3.7
# Usage: python3 server.py serverPort admin_password
# coding: utf-8
#####################################################
from os import path, remove
from socket import *
import base64
import json
import sys
import threading
import time
import datetime as dt

# Check the number of command line arguments
if len(sys.argv) != 3:
    print("Usage: python3 server.py server_port admin_password")
    exit(0)
# Server will run on this port
serverPort = int(sys.argv[1])
admin_password = sys.argv[2]
t_lock = threading.Condition()

# Store clients info in this list
clients = []

# Store the credentials into list of dictionaries
credentials = []

# Store all the thread title into this list
thread_dict = {}

# Store all the filename in format of threadtitle-filename
filename_list = []

# Store all active user
active_user = []

# store the shutdown state
shutdown = False
to_exit = False

buffer_size = 1024

# would communicate with clients after every second
UPDATE_INTERVAL = 1
timeout = False

# With the given assumption in the spec, a credentials file called credentials.txt will be available 
# in the current working directory of the server with the correct access permissions set (read and write)
# Hence, do not need to check the existance the file
f = open("credentials.txt", "r")

# Read the credentials file line by line
f1 = f.readlines()
for user in f1:
    username, password = user.split()
    user_dict = {
        "username": username,
        "password": password
    }
    credentials.append(user_dict)
f.close()

# Helper function to check if the username exist in the credentials file
def authenticate_username(username):
    found = False
    for user in credentials:
        if user['username'] == username:
            found = True
    return found

# Helper function to check if the password exist in the credentials file
def authenticate_password(username, password):
    found = False
    for user in credentials:
        if user['username'] == username:
            if user['password'] == password:
                found = True
    return found

# Helper function to add new username to the credentials file
def add_username(username):
    f = open("credentials.txt", "a")
    f.write(username)
    f.close()

    update()

# Helper function to add new password to the credentials file
def add_password(username, password):
    f = open("credentials.txt", "r+")
    for line in f:
        if line == username:
            f.write(' ' + password + '\n')
    f.close()

    update()

# Helper function to update the global credentials list
def update():
    # Empty the list
    credentials.clear()

    f = open("credentials.txt", "r")

    # Read the credentials file line by line
    f1 = f.readlines()
    for user in f1:
        line = user.split()
        # Checking the length of the current line,
        # incase a new user has just been created
        # but the password hasn't recieved yet
        if len(line) == 1:
            user_dict = {
                "username": line[0]
            }
        elif len(line) == 2:
            user_dict = {
                "username": line[0],
                "password": line[1]
            }
        credentials.append(user_dict)
    f.close()

# Helper function to check the existance of a thread inside the current directory
def exist_thread(thread_title):
    exist = False
    if path.exists("{}".format(thread_title)):
        exist = True
    return exist

# Helper function to print out which command has been issued
def print_command(username, command):
    print('{} issued {} command\n'.format(username, command))

# Helper function to create a thread
def create(username, thread_title):
    global thread_dict
    result = False
    # If the thread does not exist, create a new one
    if not exist_thread(thread_title):
        result = True
        f = open("{}".format(thread_title),"w+")
        f.write(username)
        f.close()
        thread_dict[thread_title] = []
    
    return result

# Helper function to post message
def post(username, thread_title, message):
    result = exist_thread(thread_title)
    if result:
        f = open("{}".format(thread_title),"r")
        msg_num = num_messages(thread_title) + 1

        # Can try to rewrite it with f.seek() or just write the current f before it close
        f = open("{}".format(thread_title),"a")
        f.write('\n{} {}: {}'.format(msg_num, username, message))
        f.close()

    return result

# Helper function for listing threads
def list_thread():
    exist = False
    # If the thread list is not empty
    if len(thread_dict) != 0:
        exist = True

    return exist

# Helper function to read the threads
def read(thread_title):
    result = []
    # If the thread exists
    if exist_thread(thread_title):
        f = open("{}".format(thread_title),"r")
        content = f.readlines()
        f.close()
        # Looping through the list start at the second element
        for line in content[1:]:
            result.append(line)

    return result

# Helper function to find the total number of messages in a thread
def num_messages(thread_title):
    num = 0
    f = open("{}".format(thread_title),"r")
    content = f.readlines()
    # Ignore the first line, which is the creator of the thread
    for line in content[1:]:
        line_list = line.split()
        if ":" in line_list[1]:
            num += 1
    return num

# Helper function to find the line number of the message need to be deleted
def find_line_num(thread_title, msg_num):
    line_num = 1
    f = open("{}".format(thread_title),"r")
    content = f.readlines()
    # Ignore the first line, which is the creator of the thread
    for line in content[1:]:
        line_list = line.split()
        if ":" in line_list[1]:
            if int(line_list[0]) == msg_num:
                break
        line_num += 1
    return line_num

# Helper function to check if the given threadtitle is a filename or not
def check_filename(thread_title):
    result = False
    for filename in filename_list:
        if thread_title == filename:
            result = True
    return result

# Helper function to delete a message in the thread
def delete(username, thread_title, msg_num):
    result = "DELETED"
    # If the thread title is actually a filename
    if check_filename(thread_title):
        result = "THREAD_IS_FILE"
    # Else if the thread does not exist
    elif not exist_thread(thread_title):
        result = "THREAD_NOT_EXIST"
    # Else if the thread is empty
    elif not read(thread_title):
        result = "THREAD_EMPTY"
    else:
        f = open("{}".format(thread_title),"r+")
        messages = f.readlines()
        result = msg_check(result, thread_title, username, msg_num)
        # If the result has been changed, meaning that there is an error.
        # Hence, return the function
        if result != "DELETED":
            f.close()
            return result
        f.seek(0)
        deleted = False
        # line_msg is the line number that the message need to be deleted
        line_msg = find_line_num(thread_title, msg_num)
        last_line = len(messages) - 1
        lines_looped = 0
        for line in messages:
            if line == messages[0]:
                # If the next line is the line that need to be deleted,
                # and it is the last line in the thread
                if lines_looped + 1 == line_msg and line_msg == last_line:
                    # Remove the new line character
                    line = line[:-1]
                f.write(line)
                lines_looped += 1
                continue
            line_list = line.split()
            if lines_looped != line_msg:
                # If the requested message has been deleted
                if deleted:
                    # If the current line is a POST message, decrement the message number
                    if ':' in line_list[1]:
                        line_list[0] = str(int(line_list[0]) - 1)
                    # If the previous line is the line that need to be deleted
                    if lines_looped - 1 == line_msg:
                        f.write(" ".join(line_list))
                    else:
                        f.write('\n' + " ".join(line_list))
                # Else if the next line is the line that need to be deleted,
                # and it is the last line in the thread
                elif lines_looped + 1 == line_msg and line_msg == last_line:
                    f.write(" ".join(line_list))
                else:
                    f.write(line) 
            else:
                deleted = True
            lines_looped += 1
        f.truncate()
        f.close()

    return result

# Helper function to edit the message in the thread
def edit(username, thread_title, msg_num, message):
    result = "EDITED"
    # If the thread title is actually a filename
    if check_filename(thread_title):
        result = "THREAD_IS_FILE"
    # Else if the thread does not exist
    elif not exist_thread(thread_title):
        result = "THREAD_NOT_EXIST"
    # Else if the thread is empty
    elif not read(thread_title):
        result = "THREAD_EMPTY"
    else:
        f = open("{}".format(thread_title),"r")
        message_list = f.readlines()
        result = msg_check(result, thread_title, username, msg_num)
        # If the result has been changed, meaning that there is an error.
        # Hence, return the function
        if result != "EDITED":
            f.close()
            return result
        else:
            last_line = len(message_list) - 1
            # line_msg is the line number that the message need to be deleted
            line_msg = find_line_num(thread_title, msg_num)
            edited_msg = str(msg_num) + ' ' + username + ': ' + message
            if line_msg != last_line:
                edited_msg += '\n'
            message_list[line_msg] = edited_msg
            f = open("{}".format(thread_title),"w")
            f.writelines(message_list)
            f.close()
    return result

# Helper function to determine if the message number and the username are 
# valid in order to edit or delete the corresponding message
def msg_check(result, thread_title, username, msg_num):
    total_msg = num_messages(thread_title)
    # Return an error message if the corresponding message number is invalid
    if msg_num <= 0 or msg_num > total_msg:
        return "INVALID_MSG_NUM"

    f = open("{}".format(thread_title),"r")
    msg_list = f.readlines()

    num = 1
    # Ignore the first line, which is the creator of the thread
    for line in msg_list[1:]:
        line_list = line.split()
        if ":" in line_list[1]:
            if int(line_list[0]) == msg_num:
                # Return an error message if the corresponding username is invalid
                user = line_list[1].replace(":", "")
                if user != username:
                    return "INVALID_USER"
    f.close()
    return result

# Helper function to remove the thread from the directory
def remove_thread(username, thread_title):
    global filename_list
    global thread_dict
    result = "REMOVED"
    exist = exist_thread(thread_title)
    if exist:
        f = open("{}".format(thread_title),"r")
        first_line = f.readline()
        if first_line.replace("\n", "") == username:  
            for filename in thread_dict[thread_title]:
                remove("{}".format(thread_title + '-') + filename)
                filename_list.remove(thread_title + '-' + filename)
            remove("{}".format(thread_title))
            del thread_dict[thread_title]
        else:
            result = "INVALID_THREAD_CREATOR"
    else:
        result = "THREAD_NOT_EXIST"
    return result

# Helper function to upload a file
def upload_file(username, thread_title, filename, file_content):
    global filename_list
    global thread_dict
    # Based on the given assumption in the spec, the file name will be unique for each thread.
    # Hence, do not need to check the existance a same filename in the current directory.
    f = open("{}".format(thread_title + '-' + filename),"wb")
    f.write(file_content)

    # Can try to rewrite it with f.seek() or just write the current f before it close
    f = open("{}".format(thread_title),"a")
    f.write("\n{} uploaded {}".format(username, filename))
    f.close()

    thread_dict[thread_title].append(filename)
    filename_list.append(thread_title + '-' + filename)

# Helper function to delete everything for SHT command
def clean():
    global filename_list
    global thread_dict
    for thread_title, filenames in thread_dict:
        for filename in filenames:
            remove("{}".format(thread_title + '-' + filename))
        remove("{}".format(thread_title))
    thread_dict = {}
    filename_list = []
    # remove("credentials.txt")

# Helper function to change the buffer size to a correct number of bytes in order to recv incoming file
def change_buffer(file_size):
    global buffer_size
    result = 1024
    # Only stop when the result is greater than the file length
    while file_size >= result:
        result = result * 2
    buffer_size = result

def connection_handler(connection_socket, client_address):
    global active_user
    global buffer_size
    global clients
    global shutdown
    break_loop = False
    while True:
        data = connection_socket.recv(buffer_size)
        if not data:
            # if data is empty, the socket is closed or is in the
            # process of closing. In this case, close this thread
            exit(0)

        # received data from the client, now we know who we are talking with
        data = data.decode('utf-8')
        data = json.loads(data)
        action = data['action']
        client_status = data['status']

        #get lock as we might me accessing some shared data structures
        with t_lock:
            server_message = dict()
            server_message['action'] = action

            if action == "Login":
                if client_status == "CONNECTING":
                    server_message['action'] = "Login"
                    status = "CONNECTED"
                    clients.append([client_address, connection_socket])
                    print('Client connected\n')
                elif client_status == "SENDING_USERNAME":
                    username = data['username']
                    print(type(active_user))
                    print(active_user)
                    print(type(username))
                    print('[{}]\n'.format(username))
                    print(username in active_user)
                    
                    # If the username has already logged in
                    if username in active_user:
                        status = "USER_LOGGED_IN"
                        print('{} has already logged in\n'.format(username))
                    # if the username is exist in the credentials file
                    elif authenticate_username(username):
                        status = "USER_EXIST"
                    else:
                        status = "NEW_USER"
                        add_username(username)
                        print('Created a new user')
                elif client_status == "SENDING_PASSWORD":
                    username = data['username']
                    password = data['password']

                    # If the username has already logged in
                    if username in active_user:
                        status = "USER_LOGGED_IN"
                        print('{} has already logged in\n'.format(username))
                    # if the password is correct
                    elif authenticate_password(username, password):
                        status = "SUCCESSFUL_LOGIN"
                        active_user.append(username)
                        print('{} successful login\n'.format(username))
                    else:
                        status = "INVALID_PASSWORD"
                        print('Incorrect password\n')
                elif client_status == "ADDING_NEW_PASSWORD":
                    username = data['username']
                    password = data['password']

                    add_password(username, password)

                    status = "SUCCESSFUL_LOGIN"
                    active_user.append(username)
                    print('{} successfully logged in\n'.format(username))
            elif action == "Command":
                if client_status == "CRT":
                    username = data['username']
                    thread_title = data['thread_title']
                    print_command(username, client_status)

                    result = create(username, thread_title)

                    # If the thread successfully created
                    if result:
                        status = "THREAD_CREATED"
                        print('Thread {} created\n'.format(thread_title))
                    else:
                        status = "THREAD_EXIST"
                        print('Thread {} exists\n'.format(thread_title))
                elif client_status == "MSG":
                    username = data['username']
                    thread_title = data['thread_title']
                    message = data['message']
                    print_command(username, client_status)

                    result = post(username, thread_title, message)

                    # If the message successfully posted to the thread
                    if result:
                        status = "POST_SUCCEES"
                        print('Message posted to {} thread\n'.format(thread_title))
                    else:
                        status = "THREAD_NOT_EXIST"
                        print('Thread {} does not exist\n'.format(thread_title))
                elif client_status == "LST":
                    print_command(username, client_status)
                    exist = list_thread()

                    # If there is thread inside the list
                    if exist:
                        status = "THREAD_ACTIVE"
                        server_message['threads'] = list(thread_dict.keys())
                    else:
                        status = "THREAD_INACTIVE"
                elif client_status == "RDT":
                    thread_title = data['thread_title']
                    print_command(username, client_status)

                    result = read(thread_title)

                    # If the thread exists
                    if exist_thread(thread_title):
                        status = "READ_SUCCEES"
                        server_message['thread_content'] = result
                        print('Thread {} read\n'.format(thread_title))
                    else:
                        status = "THREAD_NOT_EXIST"
                        print('Incorrect thread specified\n')
                elif client_status == "DLT":
                    username = data['username']
                    thread_title = data['thread_title']
                    msg_num = data['message_number']
                    print_command(username, client_status)

                    result = delete(username, thread_title, int(msg_num))

                    if result == "DELETED":
                        status = "MSG_DELETED"
                        print('Message has been deleted\n')
                    else:
                        status = result
                        print('Message cannot be deleted\n')
                elif client_status == "EDT":
                    username = data['username']
                    thread_title = data['thread_title']
                    msg_num = data['message_number']
                    message = data['message']
                    print_command(username, client_status)

                    result = edit(username, thread_title, int(msg_num), message)

                    if result == "EDITED":
                        status = "MSG_EDITED"
                        print('Message has been edited\n')
                    else:
                        status = result
                        print('Message cannot be edited\n')
                elif client_status == "RMV":
                    username = data['username']
                    thread_title = data['thread_title']
                    print_command(username, client_status)

                    result = remove_thread(username, thread_title)

                    if result == "REMOVED":
                        status = "THREAD_REMOVED"
                        print("Thread {} removed\n".format(thread_title))
                    else:
                        status = result
                        print('Thread {} cannot be removed\n')
                elif client_status == "UPD":
                    thread_title = data['thread_title']
                    file_size = data['file_size']
                    change_buffer(file_size)
                    
                    print_command(username, client_status)
                    
                    # If a thread with this title does not exist, send an error message
                    if exist_thread(thread_title):
                        status = "UPD_THREAD_EXIST"
                    else:
                        status = "THREAD_NOT_EXIST"
                        print('Incorrect thread specified\n')
                elif client_status == "UPD_FILE":
                    # Reset the buffer
                    buffer_size = 1024
                    username = data['username']
                    thread_title = data['thread_title']
                    filename = data['filename']
                    file_content = base64.b64decode(data['file_content'])

                    result = upload_file(username, thread_title, filename, file_content)

                    status = "UPLOAD_SUCCESS"
                    print('{} uploaded file {} to {} thread\n'.format(username, filename, thread_title))
                elif client_status == "DWN":
                    thread_title = data['thread_title']
                    filename = data['filename']
                    print_command(username, client_status)

                    if not exist_thread(thread_title):
                        status = "THREAD_NOT_EXIST"
                    elif not exist_thread(thread_title + '-' + filename):
                        status = "FILE_NOT_EXIST"
                        print('{} does not exist in Thread {}\n'.format(filename, thread_title))
                    else:
                        f = open("{}".format(thread_title + '-' + filename),"rb")
                        file_content = f.read()
                        f.close()

                        server_message['status'] = "INCOMING_FILE_SIZE"
                        server_message['file_size'] = len(file_content)
                        connection_socket.sendto(json.dumps(server_message).encode('utf-8'), client_address)

                        status = "DOWNLOAD_SUCCESS"
                        print('{} downloaded from Thread {}\n'.format(filename, thread_title))

                        f = open("{}".format(thread_title + '-' + filename),"rb")
                        file_content = f.read()
                        f.close()
                        
                        server_message['file_content'] = base64.b64encode(file_content).decode("ascii")
                elif client_status == "XIT":
                    print('{} exited\n'.format(username))
                    print('Waiting for clients\n')
                    status = "CONNECTION_END"
                    active_user.remove(username)
                    clients.remove([client_address, connection_socket])
                elif client_status == "SHT":
                    password = data['admin_password']
                    print_command(username, client_status)
                    if password != admin_password:
                        print('Incorrect password\n')
                        status = "INCORRECT_PASSWORD"
                    else:
                        print('Server shutting down\n')
                        break_loop = True
                        shutdown = True
                        clean()

            server_message['status'] = status
            
            # send message to the client
            connection_socket.sendto(json.dumps(server_message).encode('utf-8'), client_address)
            #notify the thread waiting
            t_lock.notify()
            if client_status == "XIT":
                connection_socket.close()
                break
            elif client_status == "SHT" and break_loop:
                break

# handles all incoming data and replies to those
def recv_handler():
    global t_lock
    global clients
    global serverSocket
    print('Waiting for clients')

    while True:
        # create a new connection for a new client
        connection_socket, client_address = serverSocket.accept()

        # create a new thread for the client socket
        socket_thread = threading.Thread(name=str(client_address), target=connection_handler, args=(connection_socket, client_address,))
        socket_thread.daemon = False
        socket_thread.start()

def send_handler():
    global t_lock
    global clients
    global clientSocket
    global shutdown
    global serverSocket
    global timeout
    global to_exit
    while True:
        # get lock
        with t_lock:
            # Check if the server needs to be shutdown or not
            if shutdown:
                server_message = dict()
                server_message['action'] = "Shutdown"
                for client in clients:
                    client_address = client[0]
                    connection_socket = client[1]
                    # send message to the client
                    connection_socket.sendto(json.dumps(server_message).encode('utf-8'), client_address)
                    connection_socket.close()
                clients = []
                shutdown = False
                to_exit = True
                exit(0)
            # notify other thread
            t_lock.notify()
        #sleep for UPDATE_INTERVAL
        time.sleep(UPDATE_INTERVAL)

#we will use two sockets, one for sending and one for receiving
clientSocket = socket(AF_INET, SOCK_STREAM)
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind(('localhost', serverPort))
serverSocket.listen(5)

recv_thread=threading.Thread(name="RecvHandler", target=recv_handler)
recv_thread.daemon = True
recv_thread.start()

send_thread=threading.Thread(name="SendHandler",target=send_handler)
send_thread.daemon=True
send_thread.start()
#this is the main thread
while True:
    time.sleep(0.1)
    if to_exit:
        clientSocket.close()
        serverSocket.close()
        exit(0)