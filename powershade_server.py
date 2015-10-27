import sqlite3
import time
import crypto,random,string,zlib,sys
import requests

from flask import Flask, jsonify, request, session, g, redirect, url_for, abort, render_template, flash
from flask.ext.script import Manager
from contextlib import closing



# configuration
DATABASE = 'pshlog.db'
DEBUG = True
SECRET_KEY = 'We secure the PowerShell'

# create our little application :)
app = Flask(__name__)
app.config.from_object(__name__)

#test_config
POWERSHADE_PRESHARED_KEY = "140b41b22a29beb4061bda66b6747e12"

sensors = {}

@app.before_request
def before_request():
    g.db = connect_db()

@app.teardown_request
def teardown_request(exception):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()
        
def connect_db():
    return sqlite3.connect(app.config['DATABASE'])
    
def init_db():
    with closing(connect_db()) as db:
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

@app.route('/',)
def test():
    #input = request.form['data']
    return "got it"

@app.route('/testview', methods=['GET'])
def test2():
    cur = g.db.execute("SELECT * FROM pshlog")
    rec = cur.fetchall()
    cur.close()
    content = ''
    for item in rec:
        content += str(item[1]) + str(item[2])+str(item[3])+str(item[4]) + "\n"
    #data = test
    return content
    
@app.route('/log', methods=['POST'])
def log():
    host     = request.form['host']
    attacker = request.form['attacker']
    tstamp   = int(time.time()) #request.form['tstamp']
    artifact = request.form['artifact']
    
    g.db.execute('insert into pshlog (host, attacker, tstamp, artifact) values (?,?,?,?)',[host, attacker, tstamp, artifact])
    g.db.commit()
    #flash('New entry was successfully posted')
    return "I got it"

@app.route('/dashboard/<mytitle>', methods=['GET'])
def dashboard(mytitle):
    return render_template("dashboard_base.html",pshtitle=mytitle)

@app.route('/dashboard2', methods=['GET'])
def dashboard2():
    cur = g.db.execute("SELECT * FROM pshlog")
    rec = cur.fetchall()
    # id,host,attacker,tstamp,artifact
    return render_template("pshlog.html",records=rec)
    
@app.route('/beacon', methods=['POST'])
def beacon():
    print "beacon(): ====",request.form['payload']
    plaintext = decrypt(request.form['payload'])
    terms = plaintext.split('##')
    #print terms
    host   = terms[0].split(':')[1]
    status = terms[1].split(':')[1]
    ip = request.remote_addr
    tstamp   = int(time.time()) 
    
    sensors[host] = [ip,status,tstamp]
    print "beacon(): ", sensors    
    return "Got: %s %s %s %s" % (host,ip,status,str(tstamp))

@app.route('/host', methods=['GET'])
def host():
    #dummy data
    #sensors = { "SERVER01":["192.168.1.2","MON"],"WEBSERVER":["192.168.10.2","BLO"],"DMZSERVER":["192.168.3.200","PAS"]  }
    print sensors    
    return render_template("host_list.html",mytitle="Sensors",mysensors=sensors)

@app.route('/echo', methods=['GET'])
def echo():
    print "Call echo"
    ret_data = {"value": request.args.get('echoValue')}
    return jsonify(ret_data)

@app.route('/echoindex')
def echoindex():
    return render_template('echoindex.html')
    
@app.route('/chgmode', methods=['GET'])
def changeMode():
    sensorip = request.args.get('sensorip')
    mode = request.args.get('mode')
    # trigger with mode
    #print "sensorIP:",sensorip
    #print "mode:",mode
    clientaddr = "http://" + sensorip + ":5001/trigger"
    stream = mode + ":"
    stream += ('%016x'%random.randrange(16**16))
    ciphertext = encrypt(stream)
    data = {'token':ciphertext}
    print "changeMode() Requesting ->" + clientaddr+'?token='+ciphertext
    try:
        r = requests.get(clientaddr+'?token='+ciphertext)
        print "changeMode(): back from request"
        #print "Result:" , r.text
        ret_data = {"response":r.text}
    except Exception, e:
        ret_data = {"response":str(e)}
    
    print "changeMode(): end"    
    return jsonify(ret_data)
    
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
    plaintext = zlib.decompress(plaintext)
    return plaintext

def test_trigger():
    clientaddr = 'http://192.168.166.138:5001/trigger'
    stream = "trigger:"
    stream += ('%016x'%random.randrange(16**16))
    
    ciphertext = encrypt(stream)
    
    data = {'token':ciphertext}
    
    r = requests.get(clientaddr+'?token='+ciphertext)
    print r.text      

if __name__ == '__main__':
    #test_trigger()
    manager = Manager(app)    
    manager.run()
    