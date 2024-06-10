#!/usr/bin/python3
from socket import *
from threading import *
import optparse
import time

start_time = time.time()

screenlock = Semaphore(value=1)

# Connection scan
def conScan(targetHost , targetPort):
    try:
        con = socket(AF_INET, SOCK_STREAM)
        con.connect((targetHost, targetPort))
        con.send(b'hello\r\n')
        results = con.recv(1024)
        screenlock.acquire()
        print('[+]%d/tcp open'% targetPort)
        print('[+] ' + str(results))
    except:
        screenlock.release()
        print('[-] %d/tcp closed'% targetPort)
    finally:
        screenlock.release()
        con.close()

# Port scan
def portScan(targetHost, targetPorts):
    try:
        targetIP = gethostbyname(targetHost)
    except:
        print("\n[-] Cannot resolve '%s': Unknown host" + targetHost[0])
        return
    try:
        targetName = gethostbyaddr(targetIP)
        print('\n[+] Scan results for: ' + targetName[0])
    except:
        print('\n[+] Scan results for: ' + targetIP)
    setdefaulttimeout(1)
# This part don't work well with multiple ports
    for targetPort in targetPorts:
        t = Thread(target=conScan, args=(targetHost, int(targetPort)))
        t.start()

# Main parts of the code for the user
def main():
    parser = optparse.OptionParser("usage%prog "+"-H <target host> -p <target port>")
    parser.add_option('-H', dest='targetHost', type='string', help='Specify target host')
    parser.add_option('-p', dest='targetPort', type='string', help='Specify target port(s) seperated by comma')
    (options, args) = parser.parse_args()
    targetHost = options.targetHost
    targetPorts = str(options.targetPort).split(',')
    if (targetHost == None) | (targetPorts[0] == None):
        print(parser.usage)
        exit(0)
    portScan(targetHost, targetPorts)
if __name__ == "__main__":
    main()
# Timer for the code running
end_time = time.time()
print("To scan all ports it took {} seconds".format(end_time-start_time))