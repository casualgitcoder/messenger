#!/usr/bin/python

import socket, getpass, argparse, random, base64, os
import threading, time, scrypt, json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization

# argument parsing
parser=argparse.ArgumentParser()
parser.add_argument('-u', default='ram',type=str, help='provide the user name for the connection')
parser.add_argument('-sip', default='127.0.0.1', type=str, help='provide the ip address of the server')
parser.add_argument('-sp', default=8080, type=int, help='provide the port number of the server')
args=parser.parse_args()

# checking nonce
def checknonce1(snonce,unonce):
    if snonce==unonce+x:
        return True
    else: return False

#generating DH keys
def gendh():
    pk = ec.generate_private_key(ec.SECP384R1(), default_backend())
    puk = pk.public_key()
    spuk = puk.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return pk,spuk

#generating shared key using DH
def gensk(pk,upuk):
    puk = serialization.load_pem_public_key(upuk,backend=default_backend())
    sk = pk.exchange(ec.ECDH(), puk)
    sk = scrypt.hash(sk,sk,buflen = 32)
    return sk

#encrypting and serialization
def encryptor (ptext,key):
    iv=os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    cipher = cipher.encryptor()
    ctext = cipher.update(ptext) + cipher.finalize()
    tag = cipher.tag
    return (ctext,iv,tag)

def encryptor1 (dict,key):
    data=json.dumps(dict)
    ct,iv,tag=encryptor(data,key)
    data={'ct':enco(ct),'iv':enco(iv),'tag':enco(tag)}
    data=json.dumps(data)
    return data

#decrypting and de-serialization
def decryptor (ctext,key,iv,tag):
    dcipher = Cipher(algorithms.AES(key), modes.GCM(iv,tag), backend=default_backend()).decryptor()
    ptext = dcipher.update(ctext) + dcipher.finalize()
    return ptext

def decryptor1 (data,key):
    data=json.loads(data)
    ptext=decryptor(deco(data['ct']),key,deco(data['iv']),deco(data['tag']))
    data=json.loads(ptext)
    return data

#generate temporary key which acts as a channel for DH exchange
def keygen (un,pas,nonce):
    tsk=scrypt.hash(un,pas,buflen=32)
    sk=scrypt.hash(str(nonce),tsk,buflen=32)
    return sk

#base64 encode and decode
def enco (ptext):
    return (base64.b64encode(ptext))

def deco (etext):
    return (base64.b64decode(etext))

#fetching other user's data
def getuserdata(addr,type):
    data=list[addr][type]
    return data

#fetching nonce value
def getnonce(addr,nonce):
    x=getuserdata(addr,'x')
    nnonce=nonce+x
    list[addr]['nonce']=nnonce
    return nnonce

#function to handle input
def cmd(input):
    nonce=getuserdata(server,'nonce')
    nnonce=getnonce(server,nonce)
    data={'data':input,'nonce':nnonce}
    key=getuserdata(server,'sk')
    data=encryptor1(data,key)
    client_soc.sendto(data,server)
    if input=="logout": return True
    else: return False

#function for send command
def checksend(sun):
    for i in list:
        if list[i]['un'] == sun:
            return i
    else: return False

def cmdsend(input):
    global smessage
    input=input.split()
    sun=input[1]
    smessage=" ".join(input[2:])
    check=checksend(sun)
    if check != False: finalsend(check)
    else:
        nonce=getuserdata(server,'nonce')
        nnonce=getnonce(server,nonce)
        data={'data':'send','sun':sun,'nonce':nnonce}
        key=getuserdata(server,'sk')
        data=encryptor1(data,key)
        client_soc.sendto(data,server)

#check nonce
def checknonce(addr,nonce):
    x=getuserdata(addr,'x')
    pnonce=getuserdata(addr,'nonce')
    nnonce=pnonce+x
    if nonce == nnonce: return True
    else: return False

#fuction to handle ticket
def sendticket(data):
    tempkey=deco(data['key'])
    snonce=data['snonce']
    saddr=data['saddr']
    un=data['un']
    saddr=(saddr[0],saddr[1])
    pk, spuk =gendh()
    ticket = data['ticket']
    data1={"dhpkey":enco(spuk),"snonce":snonce}
    data2=ticket
    data1=encryptor1(data1,tempkey)
    data={'cmd':'send1','data1':data1,'data2':data2}
    data=json.dumps(data)
    client_soc.sendto(data,saddr)
    list.update({saddr:{'un':un,'dhpk':pk,'sk':tempkey}})

# receiving function - sub of rdecrypt1(all data received through socket is handled here)
def rdecrypt(data,addr):
    key=getuserdata(addr,'sk')
    data=decryptor1(data,key)
    nonce=data['nonce']
    if data['cmd']=="list":
        if checknonce(addr,nonce):
            list[addr]['nonce']=nonce
            data=data['data']
            return data
        else: return False
    elif data['cmd']=="logout" and data['data']=="logout ack" and addr==server and checknonce(addr,nonce):
        print "loggedout"
        return True
    elif data['cmd']=='send':
        list[addr]['nonce']=nonce
        sendticket(data)
    elif data['cmd']=='send2':
        x=data['x']
        puk=data['dhpkey']
        list[addr].update({'nonce':nonce,'x':x})
        pk=list[addr]['dhpk']
        list[addr]['sk']=gensk(pk,deco(puk))
        finalsend(addr)
    elif data['cmd']=='realsend':
        if checknonce(addr,nonce):
            list[addr]['nonce']=nonce
            data=data['data']
            data= list[addr]['un']+": "+data
            return data
        else: return False
    elif data['cmd']=='servermsg':
        if checknonce(addr,nonce):
            list[addr]['nonce']=nonce
            ruser=data['data']
            removeuser(ruser)
    else: return False

def removeuser(ruser):
    for i in list:
        if list[i]['un']==ruser:
            addr=i
            break
    try:
        del list[addr]
    except:
        pass

# the final fuction which actually sends to a peer
def finalsend(addr):
    nonce=getuserdata(addr,'nonce')
    nnonce=getnonce(addr,nonce)
    key=getuserdata(addr,'sk')
    data={'cmd':'realsend','data':smessage,'nonce':nnonce}
    data=encryptor1(data,key)
    client_soc.sendto(data,addr)

# receiving function (all data received through socket is handled here)
def rdecrypt1(data,addr):
    if addr in list:
        data=rdecrypt(data,addr)
        return data
    else:
        data=json.loads(data)
        data1=data['data1']
        data2=data['data2']
        data2=decryptor1(data2,ukey)
        skey=deco(data2['key'])
        saddr=data2['addr']
        snonce=data2['nonce']
        un=data2['un']
        data1=decryptor1(data1,skey)
        if data1['snonce'] != snonce: return False
        pk, spuk=gendh()
        sk=gensk(pk,deco(data1['dhpkey']))
        x=random.randint(10**10,10**11)
        list.update({addr:{'un':un,'sk':sk,'nonce':snonce,'x':x}})
        data={'cmd':'send2','dhpkey':enco(spuk),'x':x,'nonce':snonce}
        data=encryptor1(data,skey)
        client_soc.sendto(data,addr)

# function for sending data
def sending():
    while True:
        time.sleep(0.3)
        input=raw_input('-->')
        if input[0:4] == 'send':
            if input.split()[1]==args.u:
                print "cant send message to yourself"
                continue
            else:
                cmdsend(input)
        else:
            data=cmd(input)
            if data==True: break


#function for receiving data
def receving():
    while True:
        data,addr=client_soc.recvfrom(1024)
        data=rdecrypt1(data,addr)
        if data == True: break
        elif data == False: continue
        else:
            if data != None:
                print "<--", data

#loggin
def loginreq(puzzle,addr,snonce,unonce):
    global ukey
    answer = eval(puzzle)
    pt = {'puzzle':answer,'un':args.u,'nonce':snonce}
    pt = json.dumps(pt)
    cipher_text,iv,tag = encryptor(pt,skey)
    data = {'ct':enco(cipher_text),'iv':enco(iv),'tag':enco(tag)}
    data = json.dumps(data)

    upk, upuk = gendh()
    ukey=keygen(args.u,pas,snonce)

    pt={'puzzle':answer,'dhkey':enco(upuk),'nonce':unonce}
    pt=json.dumps(pt)
    cipher_text,iv,tag=encryptor(pt,ukey)
    data1={'ct':enco(cipher_text),'iv':enco(iv),'tag':enco(tag)}
    data1=json.dumps(data1)

    data={"puzzle":answer,"id":data,"dk":data1}
    client_soc.sendto(json.dumps(data),server)

    data2,addr=client_soc.recvfrom(1024)
    if "!@#$" in data2:
        print data2.strip('!@#$')
        return False
    data2=json.loads(data2)
    data21=json.loads(data2['data1'])
    data22=json.loads(data2['data2'])
    data21=decryptor(deco(data21['ct']),ukey,deco(data21['iv']),deco(data21['tag']))
    data21=json.loads(data21)
    spuk=deco(data21['dhkey'])
    salt=deco(data21['salt'])
    shared_key=gensk(upk,spuk)
    data22=decryptor(deco(data22['ct']),shared_key,deco(data22['iv']),deco(data22['tag']))
    data22=json.loads(data22)
    snonce=data22['nonce']
    if snonce!=unonce+x: return False

    spas=scrypt.hash(pas,salt)
    unonce=snonce+x
    data3={'spas':enco(spas),'nonce':unonce}
    pt=json.dumps(data3)
    cipher_text,iv,tag=encryptor(pt,shared_key)
    pt={'ct':enco(cipher_text),'iv':enco(iv),'tag':enco(tag)}
    pt=json.dumps(pt)
    client_soc.sendto(pt,server)
    data,addr=client_soc.recvfrom(1024)
    data=json.loads(data)
    snonce=data['nonce']
    ncheck=checknonce1(snonce,unonce)
    print "successfully logged in"
    list={addr:{'un':'server','sk':shared_key,'nonce':snonce,'x':x}}
    return list

client_soc=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
server=(args.sip,args.sp)
pas=getpass.getpass()
client_soc.sendto("loginreq",server)
cp=client_soc.getsockname()[1]
cip=socket.gethostbyname(socket.getfqdn())
skey="1\xe0\x7f\xa4\x7f\xa5v\xb4Z\x06)\xa7\xbe\xfb\xde\xe8"
snonce=random.randint(10**16,10**17)
x=random.randint(10**10,10**15)
unonce=snonce+x
puzzle,addr = client_soc.recvfrom(1024)
rdata=loginreq(puzzle,addr,snonce,unonce)
if type(rdata)==dict:
    list=rdata
if rdata!=False or rdata!=None:
#starting the receiving and sending threads
    r=threading.Thread(target=receving)
    s=threading.Thread(target=sending)
    s.start()
    r.start()

