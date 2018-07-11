from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
import os, scrypt, base64, pickle
import sys

hkey=os.urandom(16)
salt=os.urandom(16)
user,pas=raw_input("username"),raw_input("password")

sp=scrypt.hash(pas,salt)
h = hmac.HMAC(hkey,hashes.SHA512(), backend=default_backend())
h.update(sp)
hp = h.finalize()

symkey=scrypt.hash(user,pas,buflen=32)
stuff={user:{"symkey":base64.b64encode(symkey),"salt":base64.b64encode(salt),"hkey":base64.b64encode(hkey),"hp":base64.b64encode(hp)}}

temp={}

f=open("data.txt","ab+")
file=f.read()
f.close()
if len(file)!=0:
 temp=pickle.loads(file)

temp.update(stuff)
f=open("data.txt","wb")
pickle.dump(temp,f)
f.close()
