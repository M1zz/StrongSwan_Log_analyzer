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
saChange = False
File_INIT = True
valid_dic = {}

hostname = socket.gethostname()

squence = True

log_temp = []

def write_file(log_storage):
    """
        Write file as csv form line by line
        The Identifier is [;;]
    """

    global walker
    filename = str(walker)[:-2]+".csv"

    try: 
        f = open('./result/'+filename, 'r')
    except IOError:
        f = open('./result/'+filename, 'w')
        header = "Phase;;IP;;Time;;Category;;Message;;Status\n"
        f.write(header)
        f.close()
    f = open('./result/'+filename, 'a')
    #print("start file write:",filename)
    count = 0
    length = len(log_storage)
    print ("line :",log_storage)
    for item in log_storage:
        #print(str(word))
        f.write(str(item))
        if (count != length-1):
            f.write(";;")
        count += 1
    f.write("\n")
    #print("File Write Done!","filename : ",filename)
    f.close()


def null_checker(Phase, IP, Time, Category, Message, Status):
    """
    Check null and return False
    """

    if (Phase is '' or  IP is '' or 
        Time is '' or Category is '' or
        Message is '' or  Status is ''):
        return True
    return False


def item_init():
    """
        initiating all global variables
    """

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


def phase_checker():
    """
        Checking phase is null or not
        if there is a error initiate the variables
    """

    global Phase
    global IP
    global Time
    global Category
    global Message
    global Status

    if (null_checker(Phase, IP, Time, Category, Message, Status)):
        Status = "fail"
        form_maker(Phase,IP,Time,Category,Message,Status)
        item_init()
    else:
        form_maker(Phase,IP,Time,Category,Message,Status)


def log_analyzer(line):
    """
    Analyze and make it Phase;;IP;;Time;;Category;;Message;;Status
    """

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
    global saChange
    global valid_dic

    global log_temp

    sentence = ""
    log_list = []
    global security
    #log_storage  = []

    try:
        # Get the time
        Time = line[0].replace(" ","/")

        # Get the keyWord IKE_AUTH (keyWord : authentication)
        keyWord_one = line[3][0]
        keyWord_two = str(line[3][0]) + " " + str(line[3][1])

        if (len(line[3]) > 4):
            sentence = ""
            for word in range(3):
                sentence += str(line[3][word]) + ' '
            sentence = sentence[:-1]
            
        # All log need IP and check saChange
        if (line[3][2] == "initiating" and line[3][0] != IP and saChange == False):
            IP = str(line[3][0])
            saChange = True

        # Get the whole Sentence 
        cmpSentence = str(line[3][0]) +" "+\
                      str(line[3][1]) +" "+\
                      str(line[3][2])
        
        result = line[3][3]
          
        
        if (keyWord_two == "DH group"):
            security = str(line[3][5])


        # Check IKE_INIT and trigger
        if (cmpSentence == "parsed IKE_AUTH request" and result == '1'):
            IKE_INIT_FLAG = True
            Phase = "IKE_INIT"
            # Phase IKE_INIT
            Category = "Security"
            Message = security
            Status = "Successful"

            # Status fail case 
            phase_checker()

        # Get result of authentication
        if (keyWord_one == "authentication"):
            auth_result = line[3][8]

            
        # For the IKE_INIT AND IKE_AUTH
        sentence_length = len(line[3])
        if (keyWord_one == "authentication" and auth_result == "successful" and sentence_length == 9):
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
            phase_checker()               
 
            IKE_AUTH_FLAG = True
            IKE_SA = True

        #print("check :",sentence)         
        if (sentence == "signature validation failed,"):
            # Phase IKE_INIT
            Phase = "IKE_AUTH"
            Category = "Certification"
            Message = sentence
            Status = "fail"

            # Status fail case 
            phase_checker()
        elif (sentence == "no trusted RSA"):
            # Phase IKE_INIT
            Phase = "IKE_AUTH"
            Category = "Certification"
            Message = sentence
            Status = "fail"

            # Status fail case 
            phase_checker()


        #print("key : ",keyWord_two)
        if (keyWord_two == "maximum IKE_SA"):
            #print "[IKE_AUTH]IKE Lifetime :",line[3][3] 
            Category = "Lifetime"
            lifetime = str(line[3][3])[:-1]
            Message = lifetime
            Status = "Successful"
            
            phase_checker()    

        if (keyWord_one == "CHILD_SA" and IKE_AUTH_FLAG == True): 
            
            spi = line[3][5]+"n",line[3][6]+"ut" 
            Category = "SPI"
            Message = str(spi)
            
            spi_in = str(line[3][5])[:-2]
            #print("spi_in",spi_in) 
 
            spi_out = str(line[3][6])[:-2]
            #print("spi_out",spi_out) 

            valid_dic[spi_in] = True
            valid_dic[spi_out] = True

            #print("dic",valid_dic)

            Status = "Successful"
            
            phase_checker()   
                   
            #print("KEY",IKE_SA,keyWord_two) 
            Phase = "IKE_SA"
            Category = "Validation"
            Message = "Valid"
            Status = "Successful"
        
            IKE_SA = True
    
            phase_checker()    
            
        if (keyWord_two == "deleted SAD"):
            spi = line[3][5]

        if (keyWord_two == "deleted SAD" and valid_dic[spi]):
            saChange = False
            
            valid_dic[spi] = False

            log_temp = log_temp[:-1]

            Phase = "IKE_SA"
            Category = "Validation"
            Message = spi
            Status = "Deleted"
            #print("KEY : ",IKE_SA)
            phase_checker()
       
        if (keyWord_two == "deleting IKE_SA" and IKE_SA == True):
            saChange = False
            log_temp = log_temp[:-1]

            Phase = "IKE_SA"
            Category = "Validation"
            Message = "Invalid"
            Status = "Deleted"
            #print("KEY : ",IKE_SA)
            phase_checker()


    except:
        pass





def form_maker(Phase, IP, Time, Category, Message,Status):
    """
        To write the file make the form
    """
    
    write_list = []
    write_list.append(Phase)
    write_list.append(IP)
    write_list.append(Time)
    write_list.append(Category)
    write_list.append(Message)
    write_list.append(Status)

    write_file(write_list)
  

def follow(file_data):
    """
    Follow the syslog and analyze it
    """

    #file_data.seek(0,2)
    while True:
        line = file_data.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line


def preprocess_line(line):
    """
    Get a line from syslog throw meaningless log
    Make a log to form as list
    """

    global hostname

    temp_log = []

    # Remove space
    line_data = line.strip().split(hostname)
 
    # Time creater
    if(line_data[0] is not None):
        time = []
        date = line_data[0].split(' ')

        for item in date:
            if (item is not ''):
                time.append(item)

        time = time[0] + ' ' + time[1] + ' ' + time[2]
        datetime_object = datetime.strptime('2017 '+time, '%Y %b %d %H:%M:%S')
    
        temp_log.append(str(datetime_object))   
 
    # Content classifier
    #print("line : ",line_data,len(line_data))
    if(line_data[1] is not None):
        
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
           

def read_file():
    """
    Read syslog file to analyze because 
    all the log from strong swan stored 
    to syslog
    """

    file_data = open("/var/log/syslog","r")
    
    return file_data

def main():
    """
    The main function of analyzer
    """

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
        #print("read : ",processed_line)
        log_analyzer(processed_line)

    print("Analyzing is over")

if __name__ == "__main__":
    main()
