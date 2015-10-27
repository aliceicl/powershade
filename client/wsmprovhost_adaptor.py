import subprocess
import sys
import string
import requests

CONFIG_FILE = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\config.txt"

def getConfig(key):
    try:
        fi = open(CONFIG_FILE,'r')
        for line in fi:
            k,v = line.strip().split(':')
            if k==key:
                return v
        fi.close()
        return False
    except Exception,e:
        print str(e)
        return False

def psh_adapter(args):
    RELOCATE_PSH = "C:\\Windows\\System32\\" + str(getConfig("RELOCATE_WSMPROVHOST"))
    if (getConfig("MODE")=="BLOCK"):
        exit(0)
    else:
        wsmprovhost_pid = subprocess.Popen([RELOCATE_PSH,args[1]]).pid
    try:
        url  = str(getConfig('SENSORPROTOCOL'))+"://localhost:"+str(getConfig('SENSORPORT')) + "/attach_wsmprovhost?pid="
        url += str(wsmprovhost_pid)
        r = requests.get(url)
        #print "C2-Response:" ,r.text
    except Exception,e:
        print "wsmprovhost Error:",str(e)

if __name__ == '__main__':
    psh_adapter(sys.argv)
