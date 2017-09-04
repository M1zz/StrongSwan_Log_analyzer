# Set the Import file
from datetime import datetime
import time as tm
import os
# modify
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

squence = True

"""
File update checker
"""
def file_update_checker():
    global file_stat
    if file_stat == os.stat(path+'syslog').st_ino:
        return False
    else:
        file_stat = os.stat(path+'syslog').st_ino
        print("file is updated!",file_stat,os.stat(path+'syslog').st_ino)
        return True

"""
Valid checker is time and turn ckecker
"""
def valid_checker(datetime_object):
    time = tm.mktime(datetime_object.timetuple())
    global walker
    global squence
    # Later
    if time - walker >= 0:
        print("Time is Ok!","Time : ",time,"Walker : ",walker)
        squence = True
        return time
    # Wrong
    else:
        print ("Time Reverse Error!","Time : ",time,"Walker : ",walker)
        squence = False
        return walker


"""
Save the point and read data
"""
def read_update():
    global fp
    if fp == '':
        print('file pointer is null')
        return read_data()
    else:
        return read_old()        


def read_old():
    log_list = []

    for line in fp:
        temp_log = []
        # Remove space
        line_data = line.strip().split(' ')

        # Time converter
        if(line_data[0] is not 'null' and line_data[1] is not 'null' and line_data[2] is not 'null'):

            time = line_data[0]+' '+line_data[1]+' '+line_data[2]
            datetime_object = datetime.strptime('2017 '+time, '%Y %b %d %H:%M:%S')
            # Check the Vaild
            if (count == 0):
                time = valid_checker(datetime_object)
                count += 1
            walker = tm.mktime(datetime_object.timetuple())
        temp_log.append(time)

        # Merge Time
        try:
            host = line_data[4]
            temp_log.append(host)

            category = line_data[5]
            temp_log.append(category)

            message = line_data[6:]
            temp_log.append(message)

            log_list.append(temp_log)
        except:
            pass

    return log_list

"""
Read syslog and return data, form of list
"""
def read_data():
    global walker
    log_list = []

    # Open file
    with open(path+'/syslog') as fp:
        count = 0
        for line in fp:
            temp_log = []
            # Remove space
            line_data = line.strip().split(' ')
            
            # Time converter
            if(line_data[0] is not 'null' and line_data[1] is not 'null' and line_data[2] is not 'null'):
                
                time = line_data[0]+' '+line_data[1]+' '+line_data[2]
                datetime_object = datetime.strptime('2017 '+time, '%Y %b %d %H:%M:%S')
                # Check the Vaild
                if (count == 0):
                    time = valid_checker(datetime_object)
                    count += 1
                walker = tm.mktime(datetime_object.timetuple())
            temp_log.append(time)

            # Merge Time
            try:
                host = line_data[4]
                temp_log.append(host)
            
                category = line_data[5]
                temp_log.append(category)
            
                message = line_data[6:]
                temp_log.append(message)

                log_list.append(temp_log)
            except:
                pass
    #print (log_list)
    return log_list


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
        f = open(filename, 'r')
    except IOError:
        f = open(filename, 'w')
        header = "Phase;;IP;;Time;;Category;;Message;;Status\n"
        f.write(header)
        f.close()
    f = open(filename, 'a')
    print("start file write:",filename)

    for item in log_storage:
        count = 0
        for word in item:
            length = len(item)
            count += 1 
            #print(str(word))
            f.write(str(word))
            if (count != length):
                f.write(";;")
        #print ("line : ",item)
        f.write("\n")
    print("File Write Done!","filename : ",filename)
    f.close()


def analyzer(data):
    global walker
    
    global PHASE
    global IP
    global Time
    global Category
    global Message
    global Status
    # Init the variable
    #global IKE_INIT_FLAG
    #global IKE_AUTH_FLAG
    #global IKE_SA
    #global keyChange

    #global log_temp
    #global log_list
    global log_storage

    # Init the variable
    IKE_INIT_FLAG = False
    IKE_AUTH_FLAG = False
    IKE_SA = False
    keyChange = False

    log_temp = []
    log_list = []
    #log_storage  = []

    for line in data:        
        try:
            # Get the time
            Time = line[0].replace(" ","/")
            
            # All log need IP and check keyChange
            if (line[3][2] == "initiating" and line[3][0] != IP and keyChange == False):
                # print "======================="
                IP = str(line[3][0])
                keyChange = True
                #print "IP Changed!",IP
                
            #else:
                #log_list.append(IP)
            
            # Get the whole Sentence 
            cmpSentence = str(line[3][0]) +" "+ str(line[3][1]) +" "+ str(line[3][2])
            result = bool(line[3][3])

            # Check IKE_INIT and trigger
            if (cmpSentence == "parsed IKE_AUTH request" and result == True):
                IKE_INIT_FLAG = True
                Phase = "IKE_INIT"
                #print("IKE_INIT_FLAG : ",IKE_INIT_FLAG)
            
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
                #print("$%^$%^",keyWord,auth_result,sentence_length)
                # Add elements
                log_temp.append(Phase)
                log_temp.append(IP)
                log_temp.append(Time)
                Category = "Encryption"
                log_temp.append(Category)
                
                Message = str(line[3][7])
                log_temp.append(Message)
                
                Status = "Successful"
                log_temp.append(Status)
                

                # Status fail case 
                if (Phase is not "" and IP is not "" and Time is not "" and Category is not "" and Message is not ""):
                    log_storage.append(log_temp)
                    Status = "fail"
                    log_temp = []
                # Phase IKE_AUTH
                Phase = "IKE_AUTH"
                log_temp.append(Phase)
                log_temp.append(IP)
                log_temp.append(Time)
                
                Category = "Certification"
                log_temp.append(Category)

                certification = str(str(line[3][2])+str(line[3][3])+str(line[3][4])+str(line[3][5]))
                Message = certification
                log_temp.append(Message)

                Status = "Successful"
                log_temp.append(Status)
                
                if (Phase is not "" and IP is not "" and Time is not "" and Category is not "" and Message is not ""):
                    log_storage.append(log_temp)
                    Status = "fail"
                    log_temp = []
                
                keyWord = ""
                auth_result = ""
                IKE_AUTH_FLAG = True
                IKE_SA = True
            
            if (keyWord == "maximum" and IKE_AUTH_FLAG == True):
                #print "[IKE_AUTH]IKE Lifetime :",line[3][3]
                
                log_temp.append(Phase)
                log_temp.append(IP)
                log_temp.append(Time)
                
                Category = "Lifetime"
                log_temp.append(Category)

                lifetime = str(line[3][3])[:-1]
                Message = lifetime
                log_temp.append(Message)

                Status = "Successful"
                log_temp.append(Status)
                if (Phase is not "" and IP is not "" and Time is not "" and Category is not "" and Message is not ""):
                    log_storage.append(log_temp)
                    Status = "fail"
                    log_temp = []
            
            if (keyWord == "CHILD_SA" and IKE_AUTH_FLAG == True): 
                #print "[IKE_AUTH]SPI : ",line[3][5]+"n",line[3][6]+"ut"
                spi = line[3][5]+"n",line[3][6]+"ut" 
                
                log_temp.append(Phase)
                log_temp.append(IP)
                log_temp.append(Time)
                
                Category = "SPI"
                log_temp.append(Category)

                Message = str(spi)
                log_temp.append(Message)

                Status = "Successful"
                log_temp.append(Status)
                
                if (Phase is not "" and IP is not "" and Time is not "" and Category is not "" and Message is not ""):
                    
                    log_storage.append(log_temp)
                    Status = "fail"
                    log_temp = []
                
                Phase = "IKE_SA"
                log_temp.append(Phase)
                log_temp.append(IP)
                log_temp.append(Time)
                
                Category = "Validation"
                log_temp.append(Category)

                Message = "Valid"
                log_temp.append(Message)

                Status = "Successful"
                log_temp.append(Status)
                
                if (Phase is not "" and IP is not "" and Time is not "" and Category is not "" and Message is not ""):
                    
                    log_storage.append(log_temp)
                    Status = "fail"
                    log_temp = []


                # print "[IKE_AUTH]Result : ",IKE_AUTH_FLAG
                # print "[IKE_SA]Reuslt : VALID"
                
                Status ="Successful"
                if(len(log_list) == 6):
                    log_list.insert(0,IP)
                #print(len(log_list))
                #log_storage.append(log_list)
                log_temp = log_list
                log_list = []
                # print "======================="
    
            if (keyWord_two == "deleting IKE_SA" and IKE_SA == True):
                # print "<< [IKE_SA]Result : DELETED >>"
                keyChange = False
                IKE_SA = False
                log_temp = log_temp[:-1]
                
                Phase = "IKE_SA"
                log_temp.append(Phase)
                log_temp.append(IP)
                log_temp.append(Time)
                
                Category = "Validation"
                log_temp.append(Category)

                Message = "Invalid"
                log_temp.append(Message)

                Status = "Deleted"
                log_temp.append(Status)
                
                if (Phase is not "" and IP is not "" and Time is not "" and Category is not "" and Message is not ""):
                    log_storage.append(log_temp)
                    Status = "fail"
                    log_temp = []
            
        except:
            pass
        
    #if (IKE_INIT_FLAG == False):
        #print "[IKE_INIT]Result : ",IKE_INIT_FLAG
    #if (IKE_AUTH_FLAG == False):
        #print "[IKE_AUTH]Result : ",IKE_AUTH_FLAG
        #print "[IKE_SA]Reuslt : INVALID"
    print log_storage 
    return log_storage


"""
The main process
"""

def main():
    
    global walker
    global squence
    global update 

    while(True):
        # File update check
        if update: 
            # Read the data
            data = read_update()

            # Get client's list
            client_list = getClient_data(data)

            log_result = analyzer(data)
            #print("log_result : ",log_result)
            if (squence):
                write_file(log_result)
            #print ("walker : ", walker)

        update = file_update_checker() 
if __name__ == "__main__":
    main()
