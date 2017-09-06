

import time

def follow(file_data):
    file_data.seek(0,2)
    while True:
        line = file_data.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

def main():
    # Read file
    file_data = open("/var/log/syslog","r")
    # print log
    loglines = follow(file_data)
    for line in loglines:
        print (line) 

if __name__ == "__main__":
    main()

