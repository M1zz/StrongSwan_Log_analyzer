# Set the Import file
from datetime import datetime
import time as tm
import os

# global valiable
walker = 0
Phase = ""
IP = ""
Time = ""
Category = ""
Message = ""
Status = "Fail"

log_temp = []
log_list = []
log_storage  = []


"""
Read syslog and return data, form of list
"""
def read_data():
    global walker
    log_list = []

    # Open file
    with open('./log/syslog') as fp:
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
    return log_list


"""
Valid checker is time and turn ckecker
"""
def valid_checker(datetime_object):
    time = tm.mktime(datetime_object.timetuple())
    global walker
    global squence
    # Later
    if time - walker >= 0:
        #print("Time is Ok!","Time : ",time,"Walker : ",walker)
        squence = True
        return time
    # Wrong
    else:
        #print ("Time Reverse Error!","Time : ",time,"Walker : ",walker)
        squence = False
        return walker

"""
Get the all list of client
"""

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
Monitoring
"""
def monitoring(data,client_list):
    number = len(client_list)
    print(number)
    clear = lambda: os.system('clear')
    #clear()
    for client in client_list:
        for line in data:
            
        

"""
The main process
"""

def main():

    global walker
    global squence
    
    while(True):
        # Read the data
        data = read_data()

        # Get client's list
        client_list = getClient_data(data)
        
        # Monitoring
        monitoring(data,client_list)
           

if __name__ == "__main__":
    main()

