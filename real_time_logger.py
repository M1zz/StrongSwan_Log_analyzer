# Set the Import file
from datetime import datetime
import time
import os
import socket

# global valiable
walker = 0
Phase = ""
IP = ""
Time = ""
Category = ""
Message = ""
Status = "Fail"
update = True
fp = ''

path  = "/var/log/"
file_stat = os.stat(path+'syslog').st_ino

log_temp = []
log_list = []
log_storage  = []

# Init the variable
IKE_INIT_FLAG = False
IKE_AUTH_FLAG = False
IKE_SA = False
keyChange = False
File_INIT = True

IKE_INIT_FLAG = False
IKE_AUTH_FLAG = False
IKE_SA = False
keyChange = False

hostname = socket.gethostname()

squence = True

log_temp = []

# Get the Client List
def getClient_data(data):
    client_list = []
    for line in data:
        
        try:
            if (line[3][2] == "initiating"):
                client_list.append(line[3][0])
                #print "CLIENT IP address : ",line[3][0]
        except:
            pass
    client_list = list(set(client_list))
    return client_list


"""
Write file as csv form
The Identifier
"""
def write_file(log_storage):
    global walker
    #if  
    filename = str(walker)[:-2]+".csv"
    #f = open(filename, 'w')
    print("opening")
    try: 
        f = open('./result/'+filename, 'r')
    except IOError:
        f = open('./result/'+filename, 'w')
        header = "Phase;;IP;;Time;;Category;;Message;;Status\n"
        f.write(header)
        f.close()
    f = open('./result/'+filename, 'a')
    print("start file write:",filename)
    count = 0
    length = len(log_storage)
    for item in log_storage:
        #print(str(word))
        f.write(str(item))
        if (count != length-1):
            f.write(";;")
        count += 1
    f.write("\n")
    print("File Write Done!","filename : ",filename)
    f.close()


"""
Check null and return False
"""
def null_checker(Phase, IP, Time, Category, Message, Status):
    if (Phase is '' or  IP is '' or 
        Time is '' or Category is '' or
        Message is '' or  Status is ''):
        return True
    return False


def item_init():
    global Phase
    global IP
    global Time
    global Category
    global Message 
    global Status
    
    Phase     = "" 
    IP        = "" 
    Time      = "" 
    Category  = "" 
    Message   = "" 
    Status    = ""

"""
Analyze and make it Phase;;IP;;Time;;Category;;Message;;Status
"""
def log_analyzer(line):
    global walker
    
    global Phase
    global IP
    global Time
    global Category
    global Message
    global Status

    global log_storage

    # Init the variable
    global IKE_INIT_FLAG
    global IKE_AUTH_FLAG
    global IKE_SA
    global keyChange

    global log_temp

    log_list = []
    #log_storage  = []

    try:
        # Get the time
        Time = line[0].replace(" ","/")
            
        # All log need IP and check keyChange
        if (line[3][2] == "initiating" and line[3][0] != IP and keyChange == False):
            IP = str(line[3][0])
            keyChange = True
            #print("keyChange = True")
                
        # Get the whole Sentence 
        cmpSentence = str(line[3][0]) +" "+\
                      str(line[3][1]) +" "+\
                      str(line[3][2])
        
        result = line[3][3]

        # Check IKE_INIT and trigger
        if (cmpSentence == "parsed IKE_AUTH request" and result == '1'):
            IKE_INIT_FLAG = True
            Phase = "IKE_INIT"
           
        # Get the keyWord IKE_AUTH (keyWord : authentication)
        keyWord = line[3][0]
        keyWord_two = str(line[3][0]) + " " + str(line[3][1])

        #print ("keyWord_two",keyWord_two,keyWord) 
        # Get result of authentication
        if (keyWord == "authentication"):
            auth_result = line[3][8]

            
        # For the IKE_INIT AND IKE_AUTH
        sentence_length = len(line[3])
        if (keyWord == "authentication" and auth_result == "successful" and sentence_length == 9):
            # Phase IKE_INIT
            Category = "Encryption"
            Message = str(line[3][7])
            Status = "Successful"
            
            # Status fail case 
            if (null_checker(Phase, IP, Time, Category, Message, Status)):
                print("checker : ",Phase, IP, Time, Category, Message, Status)
                Status = "fail"
                form_maker(Phase,IP,Time,Category,Message,Status)
                item_init()
            else:
                form_maker(Phase,IP,Time,Category,Message,Status)

            # Phase IKE_AUTH
            Phase = "IKE_AUTH"
            Category = "Certification"
            certification = str(str(line[3][2])+\
                                str(line[3][3])+\
                                str(line[3][4])+\
                                str(line[3][5]))
            Message = certification
            Status = "Successful"

            # Fail case
            if (null_checker(Phase, IP, Time, Category, Message, Status)):
                log_storage.append(log_temp)
                Status = "fail"
                form_maker(Phase,IP,Time,Category,Message,Status)
                item_init()
            else:
                form_maker(Phase,IP,Time,Category,Message,Status)
                
            keyWord = ""
            auth_result = ""
            IKE_AUTH_FLAG = True
            IKE_SA = True
            
        if (keyWord == "maximum" and IKE_AUTH_FLAG == True):
            #print "[IKE_AUTH]IKE Lifetime :",line[3][3]
                
            Category = "Lifetime"
            lifetime = str(line[3][3])[:-1]
            Message = lifetime
            Status = "Successful"
                
            if (null_checker(Phase, IP, Time, Category, Message, Status)):
                Status = "fail"
                form_maker(Phase,IP,Time,Category,Message,Status)
                item_init(Phase,IP,Time,Category,Message,Status)
            else:
                form_maker(Phase,IP,Time,Category,Message,Status)
        if (keyWord == "CHILD_SA" and IKE_AUTH_FLAG == True): 
            
            spi = line[3][5]+"n",line[3][6]+"ut" 
            Category = "SPI"
            Message = str(spi)
            Status = "Successful"
               
            if (null_checker(Phase, IP, Time, Category, Message, Status)):
                Status = "fail"
                form_maker(Phase,IP,Time,Category,Message,Status)
                item_init()
            else:
                form_maker(Phase,IP,Time,Category,Message,Status)
                    
            Phase = "IKE_SA"
            Category = "Validation"
            Message = "Valid"
            Status = "Successful"
                
            if (null_checker(Phase, IP, Time, Category, Message, Status)):
                Status = "fail"
                form_maker(Phase,IP,Time,Category,Message,Status)
                item_init()
            else:
                form_maker(Phase,IP,Time,Category,Message,Status)                  

            Status ="Successful"
    
        if (keyWord_two == "deleting IKE_SA" and IKE_SA == True):
            # print "<< [IKE_SA]Result : DELETED >>"
            keyChange = False
            IKE_SA = False
            log_temp = log_temp[:-1]
                
            Phase = "IKE_SA"
            Category = "Validation"
            Message = "Invalid"
            Status = "Deleted"
            if (null_checker(Phase, IP, Time, Category, Message, Status)):
                Status = "fail"
                form_maker(Phase,IP,Time,Category,Message,Status)
                item_init()
            else:
                form_maker(Phase,IP,Time,Category,Message,Status)

    except:
        pass




"""

"""
def form_maker(Phase, IP, Time, Category, Message,Status):
    
    write_list = []
    write_list.append(Phase)
    write_list.append(IP)
    write_list.append(Time)
    write_list.append(Category)
    write_list.append(Message)
    write_list.append(Status)

    write_file(write_list)
  

"""
Follow the syslog and analyze it
"""
def follow(file_data):
    file_data.seek(0,2)
    while True:
        line = file_data.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line


"""
Get a line from syslog throw meaningless log
Make a log to form as list
"""
def preprocess_line(line):
    global hostname

    temp_log = []

    # Remove space
    line_data = line.strip().split(hostname)
 
    # Time creater
    if(line_data[0] is not 'null'):
        time = []
        date = line_data[0].split(' ')

        for item in date:
            if (item is not ''):
                time.append(item)

        time = time[0] + ' ' + time[1] + ' ' + time[2]
        datetime_object = datetime.strptime('2017 '+time, '%Y %b %d %H:%M:%S')
    
        temp_log.append(str(datetime_object))   
 
    # Content classifier
    if(line_data[1] is not ''):
        
        content = str(line_data[1]).split(' ')
        process = content[1]
        
        temp_log.append(process)
        if process == "charon:" or process == "charon-custom:":
            category = content[2]
            temp_log.append(category)

            message = content[3:]
            temp_log.append(message)
        # Do not Analyze kernel log
        else:
            #print("process : ",process)
            return ''
    return temp_log
           

"""
Read syslog file to analyze because 
all the log from strong swan stored 
to syslog
"""
def read_file():
    file_data = open("/var/log/syslog","r")
    
    return file_data


"""
The main function of analyzer
"""
def main():

    print("Start to Analyze log from Strong Swan!")
    global walker

    walker = int(time.time())

    # Read the log and file pointer
    file_data = read_file()

    # Follow the syslog
    loglines = follow(file_data)
    for line in loglines:
        # Check only StrongSwan's log
        processed_line = preprocess_line(line)
        # Analyze data
        log_analyzer(processed_line)

    print("Analyzing is over")

if __name__ == "__main__":
    main()
