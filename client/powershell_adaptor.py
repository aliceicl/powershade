from winappdbg import Color
import subprocess
import sys,os
import cmd
import psutil
import socket,requests,time,copy

DEBUG_MODE = True
CENTRALISED_MODE = True

INFO_LEVEL = 0
SUCCESS_LEVEL = 1
ERROR_LEVEL = 2

CONFIG_FILE = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\config.txt"

class PowerAdapter(cmd.Cmd):
    
    prompt = "PS " + os.environ['USERPROFILE'] + "> "

    def cmdloop(self, intro=None):
        print 'Windows PowerShell\nCopyright (C) 2009 Microsoft Corporation. All rights reserved.\n'
        return cmd.Cmd.cmdloop(self, intro)

    def emptyline(self):
        return None
    
    def precmd(self, line):
        #print 'precmd(%s)' % line
        return cmd.Cmd.precmd(self, line)

    def default(self, line):
        if (getConfig("MODE")=="BLOCK"):
            print " "
        output = powershell(line.strip().split(),False)
        if (output.find("is not recognized as the name of a") > 0):
            #error
            print_console(ERROR_LEVEL,output)
        else:
            print output
        
    def do_help(self, line):
        #print line
        inputLst = ['Get-Help'] + line.split()
        #print inputLst
        output = powershell(inputLst)
        print output

    def do_exit(self, line):
        pid  = os.getpid()
        ppid = psutil.Process(pid).ppid()
        proc = psutil.Process(ppid)
        proc.terminate()
        exit(0)
        
    def do_EOF(self, line):
        return True

    
def print_console(level,message):
    if (DEBUG_MODE == False):
        return
    try:
        if Color.can_use_colors():
            # Set black background.
            Color.bk_black()
            if (level==SUCCESS_LEVEL):
                Color.green()
                Color.light()                
            elif (level==ERROR_LEVEL):
                Color.red()
                Color.light()
            else:
                Color.white()
        print message
    except:
        print message
    finally:
        Color.reset()

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

def cmd_trace(cmd):
    host = socket.gethostname()
    attacker = ''
    tstamp = int(time.time())
    artifact = cmd
    return send_log(host,attacker,tstamp,artifact)
        
def powershell(argList,oneshot):
    if (getConfig("MODE")=="BLOCK"):
        return " "
    inputList = [str(getConfig('FALSE_POWERSHELL'))] + argList
    if (oneshot):
        logList = copy.copy(inputList)
        logList[0] = 'powershell.exe'
    else:
        logList = copy.copy(argList)
    cmd_trace(' '.join(logList))
    
    output = subprocess.Popen(inputList,stdout=subprocess.PIPE)
    outval = output.communicate()[0]
    return (outval)

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
                                                     
def main(argv):
    try:           
        if (len(argv) > 1):
            output = powershell(argv[1:],True)
            if (output.find("is not recognized as the name of a") > 0):
                #error
                print_console(ERROR_LEVEL,output)
            else:
                print output
        else:
            PowerAdapter().cmdloop()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception,e:
        print e.message()
        sys.exit(0)
    finally:
        sys.exit(0)

if __name__ == '__main__':
    main(sys.argv)

