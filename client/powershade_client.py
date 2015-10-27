from threading import Thread
import cherrypy
import random,string
import zlib
import crypto
import sys
import socket
import requests,os

#------------------------
from winappdbg.win32 import *
from ctypes import *
from winappdbg import Debug, EventHandler, HexDump, CrashDump, win32,Process

import ctypes.wintypes
import winappdbg
import psutil
import re
import string
import time
import traceback
import hashlib
import psutil
import pshutils

POWERSHADE_PRESHARED_KEY = "140b41b22a29beb4061bda66b6747e12"
SEPARATOR = "##"

MONITOR_MODE = "monitor"
BLOCK_MODE = "block"
CALL_MODE = "call"
BEACON_MODE = "beacon"

CONFIG_FILE = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\config.txt"
CENTRALISED_MODE = True

class PowerShadeServer(object):
        
    @cherrypy.expose
    def generate(self, length=8):
        return ''.join(random.sample(string.hexdigits, int(length)))

    @cherrypy.expose
    def trigger(self,token=''):
        if (len(token)>0):
            #print "trigger() Len(token): ", str(len(token))
            key = POWERSHADE_PRESHARED_KEY
            key = key[:32]
            aescrypto = crypto.AESCipher(key)
            plaintext = aescrypto.decrypt(token)
            plaintext = zlib.decompress(plaintext)
            #print "trigger(): Message ",plaintext
            mode,salt = plaintext.split(':')
            return changeConfigMode(mode)

    #--------------------------------------------------------------
    @cherrypy.expose
    def attach_wsmprovhost(self, pid):
        thread = Thread(target=monitor_wsmprovhost,args=(pid,"attach"))
        thread.start()
        return "Now attaching", pid

def monitor_wsmprovhost(pid,ref):
    system = winappdbg.System()
    system.request_debug_privileges()
    system.scan_processes()

    pshutils.print_console(pshutils.SUCCESS_LEVEL,("hooking " + str(pid)))
    #print "hooking",pid    

    myHandler =  WSMProvHostEventHandler()
    myHandler.attackers = get_pshconnection(5985) 
    thread = Thread(target=intercept_wsmprovhost,args=(pid,myHandler))
    thread.start()
    time.sleep(1)

    pshutils.print_console(pshutils.INFO_LEVEL,("back to main from " + str(pid)))
    #print "back to main from",pid
    

def changeConfigMode(mode):
    if (mode == MONITOR_MODE):
        #print "-> Monitor"
        setConfig("MODE","MONITOR")
        thread = Thread(target=callC2,args=("changeConfigMode","MONITOR"))
        thread.start()
    elif (mode == BLOCK_MODE):
        #print "-> Block"
        setConfig("MODE","BLOCK")
        thread = Thread(target=callC2,args=("changeConfigMode","BLOCK"))
        thread.start()
    elif (mode == CALL_MODE):
        #print "-> Call PowerShell"
        thread = Thread(target=callPowerShell,args=("start powershell1.exe",""))
        thread.start()
        return "PowerShell is launched"
    elif (mode == BEACON_MODE):
        #print "-> Beacon"
        thread = Thread(target=callC2,args=("changeConfigMode","beacon"))
        thread.start()
    else:
        print ""
        return "Mode is not changed"
    return "Mode is changed to " + mode

def callPowerShell(cmd,arg):
    os.system(cmd)

def callC2(fromfn,mode):
    #print fromfn + " is calling C2 > change to " + mode
    fetchC2()

def send_log(host,attacker,tstamp,artifact):
    if (CENTRALISED_MODE):
        payload = dict()
        payload['host']     = host
        payload['attacker'] = attacker
        payload['tstamp']   = tstamp
        payload['artifact'] = artifact

        url = str(getConfig('C2PROTOCOL'))+"://"+str(getConfig('C2SERVER')) + ':' + str(getConfig('C2PORT')) + "/" + str(getConfig('LOGPATH'))
        #print url
        r = requests.post(url,data=payload)
        return r.text
    else:
        return 0

def remote_trace(attackers,cmd):
    host = socket.gethostname()
    tstamp = int(time.time())
    artifact = cmd
    #print "sending:", host,attackers,tstamp
    return send_log(host,attackers,tstamp,artifact)

def setConfig(key,value):
    try:
        fi = open(CONFIG_FILE,'r')
        content = ''
        for line in fi:
            if line != '\n':
                k,v = line.strip().split(':')
                if k==key:
                    v = value
                content += str(k) + ":" + str(v) + "\n"
        fi.close()
        fi = open(CONFIG_FILE,'w+')
        fi.write(content)
        fi.close()
        return True
    except Exception,e:
        print str(e)
        return False

def getConfig(key):
    try:
        fi = open(CONFIG_FILE,'r')
        retval = None
        for line in fi:
            if line != '\n':
                k,v = line.strip().split(':')
                if k==key:
                    retval = v
        fi.close()
        return retval
    except Exception,e:
        print str(e)
        return None

def encrypt(plaintext):
    compressedtxt = zlib.compress(plaintext)
    key = POWERSHADE_PRESHARED_KEY
    key = key[:32]
    aescrypto = crypto.AESCipher(key)
    ciphertext = aescrypto.encrypt(compressedtxt)
    return ciphertext

def decrypt(ciphertext):
    key = POWERSHADE_PRESHARED_KEY
    key = key[:32]
    aescrypto = crypto.AESCipher(key)
    plaintext = aescrypto.decrypt(ciphertext)
    plaintext = zlib.compress(plaintext)
    return plaintext

def fetchC2():        
    host = socket.gethostname()
    status = getConfig("MODE")
    message = 'host:'+host+""+SEPARATOR+"status:"+status
    ciphertext = encrypt(message)
    c2url = str(getConfig('C2PROTOCOL'))+"://"+str(getConfig('C2SERVER'))+':'+str(getConfig('C2PORT'))+"/"+str(getConfig('BEACONPATH'))
    payload = dict()
    payload['payload'] = ciphertext
    r = requests.post(c2url,payload)
    #print "end fetchc2 ", r.text
#--------------------------------------------------------------
class WSMProvHostEventHandler(EventHandler):
    apiHooks = {        
       'kernel32.dll' : [
            ( 'ExitProcess',1),
            ( 'CreateProcessW' , 10 ),
            ],

       'ws2_32.dll' : [
            ( 'recv',4),
        ],
    }
    @property
    def attackers(self):
        return self._attackers

    @attackers.setter
    def attackers(self, value):
        self._attackers = value
        
    def post_recv(self, event, retval):
        #print "post_recv is called\n"
        process = event.get_process()
        tid     = event.get_tid()
        params  = event.hook.get_params(tid)

        buf    = event.get_process().peek_string(params[1])
        buflen = len(buf)
        if (buflen>1 and (buf.find('function')>=0 or buf.find('Get')>=0 or buf.find('http')>=0 or buf.find('Post')>=0)):
            eventlog = "capturing: " + str(len(buf))
            pshutils.print_console(pshutils.INFO_LEVEL,eventlog)
            #print buf
            remote_trace(list(self._attackers),buf)
        

    def pre_ExitProcess(self, event, ra, uExitCode):
        print "Pre_ExitProcess is called"
        process = event.get_process()        
        pshmemTbl = search_mem(process)
        for key in pshmemTbl:
            pshutils.print_console(pshutils.INFO_LEVEL,(key))
            pshutils.print_console(pshutils.INFO_LEVEL,(pshmemTbl[key][0]+" : "+pshmemTbl[key][1]))
            pshutils.print_console(pshutils.INFO_LEVEL,("---------------------------------------------"))
            #print key
            #print pshmemTbl[key][0],":",pshmemTbl[key][1]
            #print "---------------------------------------------"
                           
            logs = "[" + pshmemTbl[key][0] + "]: " + pshmemTbl[key][1]
            remote_trace(list(self._attackers),logs)
        print process.get_pid(), "Now exiting"

    def pre_CreateProcessW(self, event, ra, lpApplicationName, lpCommandLine, lpProcessAttributes,
                       lpThreadAttributes,bInheritHandles,dwCreationFlags,lpEnvironment,
                       lpCurrentDirectory,lpStartupInfo,lpProcessInformation
                       ):
        pshutils.print_console(pshutils.INFO_LEVEL,("pre_CreateProcessW is called"))
        #print "pre_CreateProcessW is called\n"
                        
        process = event.get_process()
        try:
            appname = process.peek_string(lpApplicationName, fUnicode=True)
            cmdline = process.peek_string(lpCommandLine, fUnicode=True)
            cmdlist = [appname,cmdline]
            pshutils.print_console(pshutils.INFO_LEVEL,cmdlist)    
            #print cmdlist
            remote_trace(list(self._attackers),cmdlist)
        except Exception, e:
            pshutils.print_console(pshutils.ERROR_LEVEL,("[-] Error in hooking " + str(e)))
            #print "[-] Error in hooking " + str(e)
          
def intercept_wsmprovhost(pid,eventHandler):
    debug = Debug(eventHandler,bKillOnExit=True)
    try:
        debug.attach(int(pid))
        debug.loop()
    except Exception,e:
        print "Error: ",str(e)
    finally:
        debug.stop()

def add_pshmemTbl(tbl,category,artifact):
    hashvalue = hashlib.sha1(artifact).hexdigest() 
    if (not tbl.has_key(hashvalue)):
        pshtuple = (category,artifact) 
        tbl[hashvalue] = pshtuple

def search_mem(process):
    system = winappdbg.System()
    system.request_debug_privileges()
    system.scan_processes()

    pshmemTbl = dict()
    
    for address, size, data in process.strings(4,2048):
        data = data.strip()
        m = re.match(r"(.*)(<S N=\"History\">)(\S+)(</S>)",data)
        if (m != None):
            #print "hist:", m.group(3)
            add_pshmemTbl(pshmemTbl,'<S N="History">',m.group(3))
        m = re.match(r"(.*?)(<S N=\"Cmd\">)(\S+)(</S>)",data)
        if (m != None):
            #print "cmd:", m.group(3)
            add_pshmemTbl(pshmemTbl,'<S N="Cmd">',m.group(3))
        if (data.find('<rsp:CommandLine') >= 0):
            add_pshmemTbl(pshmemTbl,'rsp:CommandLine',data)  
        if (data.find('<rsp:Command') >= 0):
            #print "rsp:",data
            add_pshmemTbl(pshmemTbl,'rsp:Command',data)
        if (data.find('<rsp:Arguments') >= 0):
            add_pshmemTbl(pshmemTbl,'rsp:Arguments',data)  

    return pshmemTbl

def get_pshconnection(pshport):
    p = psutil.Process(4)
    attackers = []
    for conn in p.connections():
        if (conn.laddr[1] == pshport and conn.raddr!=() and conn.laddr[0]<>conn.raddr[0]):
            pshutils.print_console(pshutils.INFO_LEVEL,(str(conn)))
            attackers.append(conn.raddr[0])
    attackers = set(attackers)
    return attackers

#--------------------------------------------------------------
def main(port):
   cherrypy.config.update({'server.socket_host': '0.0.0.0'})
   cherrypy.config.update({'server.socket_port': int(port)})
   cherrypy.quickstart(PowerShadeServer())
    
if __name__ == '__main__':
    main(str(getConfig("SENSORPORT")))

