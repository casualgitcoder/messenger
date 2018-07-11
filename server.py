#! /usr/bin/python
import socket, time, base64, pickle, scrypt
import argparse ,os , random, json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac

#generate dh keys
def gendh():
    pk = ec.generate_private_key(ec.SECP384R1(), default_backend())
    puk = pk.public_key()
    spuk = puk.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return pk,spuk

# generate shared key based on dh public and private keys
def gensk(pk,upuk):
    puk = serialization.load_pem_public_key(upuk,backend=default_backend())
    sk = pk.exchange(ec.ECDH(), puk)
    sk = scrypt.hash(sk,sk,buflen = 32)
    return sk

def deco(et):
    return base64.b64decode(et)

def enco(pt):
    return base64.b64encode(pt)

#fetch user data from database
def fetchuserdata(un):
    with open('data.txt','rb') as f:
        udata=pickle.load(f)
    return udata[un]

def usersalt(un):
    udata=fetchuserdata(un)
    return udata['salt']

def hashpas(un):
    udata=fetchuserdata(un)
    return deco(udata['hkey']),deco(udata['hp'])

# generating temp user key(used during dh key exchange)
def userkeygen(un,nonce):
     udata=fetchuserdata(un)
     ukey=scrypt.hash(str(nonce),deco(udata['symkey']),buflen=32)
     return ukey

# encrypting and adding values in dictionary and serializzing
def encryptor (ptext,key):
    iv=os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    cipher = cipher.encryptor()
    ctext = cipher.update(ptext) + cipher.finalize()
    tag = cipher.tag
    return (ctext,iv,tag)

def encryptor1 (dict,key):
    data=json.dumps(dict)
    ct,iv,tag = encryptor(data,key)
    data = {'ct':enco(ct),'iv':enco(iv),'tag':enco(tag)}
    data = json.dumps(data)
    return data

# decrypting and de-serializing
def decryptor (ctext,key,iv,tag):
    dcipher = Cipher(algorithms.AES(key), modes.GCM(iv,tag), backend=default_backend())
    dcipher = dcipher.decryptor()
    ptext = dcipher.update(ctext) + dcipher.finalize()
    return ptext

def decryptor1 (data,key):
    data=json.loads(data)
    ptext=decryptor(deco(data['ct']),key,deco(data['iv']),deco(data['tag']))
    data=json.loads(ptext)
    return data

#decrypting
def loginn(puz,key,data1):
    data1=json.loads(data1)
    ptext=decryptor(deco(data1['ct']),skey,deco(data1['iv']),deco(data1['tag']))
    return json.loads(ptext)

# checking if password is valid
def loginn1(puz,key,data2):
    data2=json.loads(data2)
    try:
        ptext=decryptor(deco(data2['ct']),key,deco(data2['iv']),deco(data2['tag']))
    except:
        return False
    return json.loads(ptext)

def loginn2(dict,key):
    data=json.dumps(dict)
    ct,iv,tag=encryptor(data,key)
    data={'ct':enco(ct),'iv':enco(iv),'tag':enco(tag)}
    return json.dumps(data)

# password verification
def loginn3(data,key):
    data=json.loads(data)
    ptext=decryptor(deco(data['ct']),key,deco(data['iv']),deco(data['tag']))
    data=json.loads(ptext)
    unonce=data['nonce']
    spas = deco(data['spas'])
    shkey,hp = hashpas(un)
    h = hmac.HMAC(shkey,hashes.SHA512(), backend=default_backend())
    h.update(spas)
    uhkey = h.finalize()
    if uhkey == hp: return True,unonce
    else: return False,False

#getting logged in user's data
def fetchloggeduser(addr,type):
    data=userlist[addr][type]
    return data

# operation on receiving list command
def listcmd(user):
    list=str()
    for i in userlist:
        if userlist[i]['un'] == user: continue
        else:
            list=list+"\n"+userlist[i]['un']
    return list

# operation upon reciving send command
def sendcmd(addr,un,sun):
    for i in userlist:
        if userlist[i]['un'] == sun:
            saddr=i
    tdata,key,nonce=ticket(addr,un,sun,saddr)
    data={'key':enco(key),'saddr':saddr,'ticket':tdata,'snonce':nonce,'un':sun}
    return data

# generating ticket
def ticket(addr,un,sun,saddr):
    nonce=random.randint(10**16,10**17)
    key=os.urandom(32)
    data={'key':enco(key),'nonce':nonce,'addr':addr,'un':un}
    skey=fetchloggeduser(saddr,'uk')
    data=encryptor1(data,skey)
    return data,key,nonce

# incrementing nonce
def getnonce(addr,nonce):
    x=fetchloggeduser(addr,'x')
    nnonce=nonce+x
    userlist[addr]['nonce']=nnonce
    return nnonce

#checking if nonce matches the expected value
def checknonce(addr,nonce):
    x=fetchloggeduser(addr,'x')
    pnonce=fetchloggeduser(addr,'nonce')
    nnonce=pnonce+x
    if nnonce == nonce:return True
    else: return False

# checking if user already logged in
def checkuserexist(un):
    for i in userlist:
        if userlist[i]['un']==un:
            data=True
            break
    else: data=False
    return data

def notifyusers(un):
    sdata={'cmd':"servermsg",'data':un}
    for i in userlist:
        key=fetchloggeduser(i,'sk')
        nonce=fetchloggeduser(i,'nonce')
        nnonce=getnonce(i,nonce)
        sdata.update({'nonce':nnonce})
        data=encryptor1(sdata,key)
        serv_socket.sendto(data,i)

# function for logged in user
def loggedinuser(addr,data):
    key=fetchloggeduser(addr,'sk')
    try:
        data=decryptor1(data,key)
    except:
        return False
    nonce=data['nonce']
    udata=data['data']
    un=fetchloggeduser(addr,'un')
    if udata=="list":
        sdata=listcmd(un)
        if checknonce(addr,nonce):
            nnonce=getnonce(addr,nonce)
            data={'cmd':'list','data':sdata,'nonce':nnonce}
            data = encryptor1(data,key)
            return data
        else: return False
    elif udata=='send':
        sun=data['sun']
        if checknonce(addr,nonce):
            nnonce=getnonce(addr,nonce)
            if not checkuserexist(sun):
                data1=sun+" - user not available"
                data={'cmd':'list','nonce':nnonce,'data':data1}
                data=encryptor1(data,key)
                serv_socket.sendto(data,addr)
                return False
            sdata=sendcmd(addr,un,sun)
            sdata.update({'cmd':'send','nonce':nnonce})
            data = encryptor1(sdata,key)
            return data
        else: return False
    elif udata=='logout':
        sdata="logout ack"
        if checknonce(addr,nonce):
            nnonce=getnonce(addr,nonce)
            sdata={'cmd':'logout','data':sdata,'nonce':nnonce}
            data = encryptor1(sdata,key)
            del userlist[addr]
            notifyusers(un)
            return data
        else: return False
    else:
        if checknonce(addr,nonce):
            nnonce=getnonce(addr,nonce)
            sdata={'cmd':'list','data':'command not supported','nonce':nnonce}
            data = encryptor1(sdata,key)
            return data
        else: return False

#argument parsing
parser=argparse.ArgumentParser(description='passing port number')
parser.add_argument('-sp',type=int, default=8080, help='Enter sever port')
sp=parser.parse_args()

#creating udp socket
sip=socket.gethostbyname(socket.getfqdn())
serv_socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
address=(sip,sp.sp)
serv_socket.bind(address)
skey="1\xe0\x7f\xa4\x7f\xa5v\xb4Z\x06)\xa7\xbe\xfb\xde\xe8"
print "server started with ip "+sip

record={}
puzzle={}
userlist={}
timer=0

while True:
    data, addr = serv_socket.recvfrom(1024)
    if int(time.time()-timer) > 10 or timer==0: puzzle={}
    timer=time.time()
    if "loginreq" in data:
         print "login received"
         puzz=str(random.randint(10**13,10**14))+"*"+str(random.randint(10**13,10**14))
         serv_socket.sendto(puzz,addr)
         puzzle={addr:puzz}
    elif addr in userlist:
         data=loggedinuser(addr,data)
         if data != False:
             serv_socket.sendto(data,addr)
         else:
             continue
    else:
         if addr in puzzle:
             try:
                 data=json.loads(data)
             except:
                 continue
             if data['puzzle']==eval(puzzle[addr]):
                 id=loginn(data['puzzle'],skey,data['id'])
                 if id['puzzle'] != data['puzzle']:
                     serv_socket.sendto ("!@#$ invalid reply", addr)
                     continue
                 snonce = id['nonce']
                 un = id['un']
                 try:
                     fetchuserdata(un)
                 except:
                     serv_socket.sendto('!@#$ user not registered',addr)
                     continue
                 if checkuserexist(un):
                     serv_socket.sendto('!@#$ user already logged in', addr)
                     continue
                 ukey=userkeygen(un,snonce)
                 dkey=loginn1(data['puzzle'],ukey,data['dk'])
                 if dkey==False:
                     serv_socket.sendto ("!@#$ wrong user credentials",addr)
                     continue
                 if dkey['puzzle'] != data['puzzle']:
                     serv_socket.sendto ("!@#$ invalid reply", addr)
                     continue
                 unonce = dkey['nonce']
                 upuk = deco(dkey['dhkey'])
                 spk,spuk = gendh()
                 shared_key = gensk(spk,upuk)
                 usalt = usersalt(un)
                 sdata21 = {'dhkey':enco(spuk),"salt":usalt}
                 sdata21 = loginn2(sdata21,ukey)
                 x=unonce-snonce
                 sdata22 = {'nonce':unonce+x}
                 sdata22 = loginn2(sdata22,shared_key)
                 sdata2={'data1':sdata21,'data2':sdata22}
                 serv_socket.sendto(json.dumps(sdata2),addr)
                 data,addr=serv_socket.recvfrom(1024)
                 a,unonce=loginn3(data,shared_key)
                 if a==False : continue
                 snonce=unonce+x
                 data={'nonce':snonce,'message':True}
                 userlist.update({addr:{'un':un,'uk':ukey,'sk':shared_key,'x':x,'nonce':snonce}})
                 serv_socket.sendto(json.dumps(data),addr)
             else: serv_socket.sendto("invalid reply",addr)
         else: serv_socket.sendto("time out",addr)

