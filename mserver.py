import socket           #Socket programming library 
import hashlib          #For MD5 Hashing
import time             #For calculating time

  
#Import thread module 
from _thread import *
import threading 
  
print_lock = threading.Lock() 

#PASS_DIGEST = b'\xabV\xb4\xd9+@q:\xccZ\xf8\x99\x85\xd4\xb7\x86'        #Hash Digest for password 'abcde'
#PASS_DIGEST = b'.\xcd\xde9Y\x05\x1d\x91?a\xb1Ey\xea\x13m'              #Hash Digest for password 'ABCDE'
PASS_DIGEST = b'\xc8\x99m6Y\x9c\x9c\xe1\xc5?\x0c\xdf\xedIu\xd7'            #Hash Digest for password 'aAZpQ'
#PASS_DIGEST = b'\xa7H\xaa"\xa5G\xd8\xb9\t\xaa<\xa93\x8f5\xf6'           #Hash Digest for password 'Pompo'
srchd_till = 0                              #The integers up to which the search has been done by workers
found = 0                                   #Indicates whether the password has been found yet
found_pass=0                                #Stores the found password when it is received 
t1 = 0

#Function that converts an integer to a 5-length string password made of alphabets
def int_to_pass(data):
    str_key = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLNMOPQRSTUVWXYZ"            #This is the order that we use to 
                                                                                #construct the string.
                                                                                #a=0, b=1, ..., z=25, A=26, ..., Z=51
    s = ""
    if data == 0:                                                               
        return "a"
        pass       
    while data > 0:                             #This function is basically a decimal to 52-base number converter 
        #print(data)                            #Since a-z and A-Z are 52 characters
        if data < 51:
            s = str_key[data] + s
            data = 0
        else:
            r = data%52
            #print(r)
            s = str_key[r] + s
            data  = (data-r)//52
    return s.rjust(5, 'a')                      #Since a=0 and every password must be of 5 letters, we pad the string with a's
  
#This function is the thread function - the one that is executed every time 
#a new thread is created, ie, when a new connection is made in the socket
def threaded(c): 
    global srchd_till                           #We will need to know how far the search is already done
    global found           
    global t1                     
     
    data = c.recv(1024) 
    #The Client sends a "hi" message the first time it makes the connection
    if data.decode('ascii') == "hi":             
        #print("OMG!!!")                    
        #c.send("hi".encode('ascii'))

        if found == 1:
            c.send(b'')
        else:
            c.send(PASS_DIGEST)                         #Server sends the digest that is to be matched
            c.send(srchd_till.to_bytes(5, "big"))       #Server sends the lower bound of the range that the worker needs to search
            srchd_till = srchd_till+100000               #Marks the assigned range as searched

        print_lock.release()                        #Ready to make a new connection

    #The client sends a "found" message if the password has been found by it
    elif data.decode('ascii') == "found":
        #print("FOUND!!!")
        t2 = time.perf_counter()
        c.send("what is it?".encode('ascii'))

        data = c.recv(1024)                         #Server receives the matching integer from the worker
        found_pass = int.from_bytes(data, "big")
        print("The required password is = "+int_to_pass(found_pass))              #Server converts the sent integer to the corresponding password
        c.send("done".encode('ascii'))

        print("Time taken to find password = "+str((t2-t1)*1000)+" ms")          

        #print('Bye1')       
        found = 1                                   #The global variables are set to indicate the password has been found
        print_lock.release() 

    #The client sends a "not found" message if the password has been found by it in the given range
    elif data.decode('ascii') == "not found":
        print("NOT FOUND :( ... Still searching ...")
        if found == 1:
            c.send(b'')
        else:
            c.send(srchd_till.to_bytes(5, "big"))       #Server sends a new range to the worker to search in
            srchd_till = srchd_till+100000               #and updates the already searched range 

        print_lock.release() 

    #If the client has not sent any data, the server terminates the socket connection with this client
    elif not data: 
        print('Bye') 
        print_lock.release()
        found  = 1       
  
    #Finally connection is closed either way
    c.close() 
  
  
def Main(): 
    x=0
    global found                                                #Main function needs to know if password has been found 
    global t1                    

    host = ""                                                   #Opens a socket at port 12345
    port = 12345
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)       
    s.bind((host, port)) 
    print("socket binded to port", port) 
  
    s.listen(5) 
    print("socket is listening") 

    while found == 0:                                           #We run this code as long as the password is not found
        #print("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEeee")
        c, addr = s.accept()                                    #Each iteration of the code is for one connection
        if x==0:
            x=1
            t1 = time.perf_counter()                            #Start counting time from the time the first connection is made

        print_lock.acquire()                                    
        #print('Connected to :', addr[0], ':', addr[1])

        start_new_thread(threaded, (c,))                        #We open new threads for each connection, so that 
                                                                #the server can parallely interact with different workers
    s.close()                                                   #The last connection is closed when password is found
  
if __name__ == '__main__': 
    Main()