import socket 
import hashlib

range = -1                                      #Stores the current working search range for the worker
PASS = b''                                      #Stores the digest to be matched, once received from the server
found = 0                                       #A flag indicating whether the password has been found yet
  
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

def Main(): 
    global range                                #The main function needs to know whether the password has been found yet 
    global found
    host = '192.12.245.172'                     
    #host = '127.0.0.1'
  
    port = 12345
  
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)            #The worker connects to the socket with the server 
    s.connect((host,port)) 
  
    s.send("hi".encode('ascii'))                                    #Worker sends "hi" as the first message when it connects
 
    try:
        PASS = s.recv(16)                                           #Receives the hash digest that needs to be matched
        if PASS == b'':
            found = 1
            s.close()
        else:
            print(PASS)                                                 
            data = s.recv(1024)                                         #Receives the range that the worker needs to search
            range = int.from_bytes(data, "big")
            print(range) 
            s.close()                                                   #Closes the socket connection for the time being 
                                                                        #to go calculate hashes for every password in the range    
    except ConnectionResetError:
        print("Password has already been found!")
        found = 1

    while found==0:                                                 #Only continue searching until the password has been found                                                         
    #range = 146174
        i = range
        flag = 0
        while i<(range+100000):                                      #The loop runs for the size of the range - we vary this for our experiments
            str_i = int_to_pass(i)
            result = hashlib.md5(str_i.encode('ascii'))             #Compute the MD5 hash of the password
            dig = result.digest()
            if dig == PASS:                                         #Check if it matches the provided digest
                flag = 1                                            #If yes, set flag to 1 and exit
                break
            i= i+1
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)        #Set up a connection again 
        if flag==1:
            #print('hey i here')                                     
            s.connect((host, port))
            s.send("found".encode('ascii'))                         #Send a "found" message if the password has been found            
            s.recv(1024)

            s.send(i.to_bytes(5, "big"))                            #Send the matching password to the server 
            found = 1                                               #Set indicator to indicate password has been found
                                                                    #So that the loop does not repeat    
        else:
            s.connect((host, port))                         
            s.send("not found".encode('ascii'))                     #Send a "not found" message if the password has not been found
            try:
                data = s.recv(1024)                                     #Receive the new search range from the server
                if data == b'':
                    found = 1;
                else:
                    range = int.from_bytes(data, "big")
                    print(range) 
            except ConnectionResetError:
                print("Password has already been found!")
                found = 1
        s.close()                                                   #Close the connection and go back to searching if 
                                                                    #password has not been found or exit if it has
  
if __name__ == '__main__': 
    Main()