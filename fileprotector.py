import os, random, struct
import sys
import fileinput
import click
import datetime as dt
from passlib.hash import pbkdf2_sha512
from hashlib import sha256
from os.path import expanduser
import logging
import re
from Crypto.Cipher import AES
from Crypto import Random
#System setup
FORMAT = '%(asctime)s - %(levelname)s - %(user)s - %(message)s'
logging.basicConfig(format=FORMAT,level=logging.INFO)
home = '/Users/amjad/git/Crypto/HOME'
usersFile = os.path.join(home,'users')
filesDB= os.path.join(home,'files')
user_id={}

def selectMod():
    if (os.path.exists(usersFile)):
        @click.command()
        @click.option('--user', help='username')
        @click.option('--password',hide_input=True,
              help='Enter a password')
        def doAuthi(user, password):
            user_id['user']=user
            if(authi(user,password)):
                logging.info('SUCCESS: %s','You are successfully logged in.',extra=user_id)
                request=input()
                commandOpt(request)
            else:
                logging.error('FAILURE: %s', 'The username or password you entered is incorrect.', extra=user_id)
                exit()
        doAuthi()
    #Create Admin if users.file doesn't exist.
    else:
        @click.command()
        @click.option('--password', prompt=True, hide_input=True,
              confirmation_prompt=True,  help='Enter a password')
        def createAdmin(password):
            addEntity('admin',password)
        createAdmin()
        exit()


def authi(user, password):
    foundUser=False
    with open(usersFile, "r") as f:
                rows = (line.strip().split(":") for line in f)
                records = [row for row in rows if row[0] == user]
                if(len(records)):
                    foundUser=True
    if foundUser:
        securedPass = records and records[0][1]
        #fromat the hash to match pbkdf2_sha512 outputs.
        hash= "$pbkdf2-sha512$10000"+securedPass[2:]
        return pbkdf2_sha512.verify(password, hash)

def addEntity(user,password):
    if(os.path.exists(usersFile) and not isAdmin()):
        logging.error('UNAUTHORIZED: %s', 'Not allowed because you do not have permission to add a user', extra=user_id)
    elif(usernameExists(user)):
        logging.error('FAILURE: %s', ('Username "%s" already exists.'%user), extra=user_id)
    else:
        usersFile = open(usersFile, 'a')
        record = generateSecPass(user,password)
        usersFile.write(record)
        usersFile.close()

def usernameExists(user):
    if (os.path.exists(usersFile)):
        with open(usersFile, "r") as f:
            for line in f:
                if(line.strip().split(":")[0]==user):
                    return True
    return False

def commandOpt(request):
    command=request.split(" ")[0]
    if command =='adduser':
        arg=request.split(" ")
        addEntity(arg[1],arg[2])
    elif command == 'setpassword':
        arg=request.split(" ")
        setPassword(arg[1])
    elif command == 'encrypt':
        arg=request.split(" ")
        encrypt_file(arg[1], arg[2])

    # elif command == 'decrypt':
    #
    # elif command == 'authorize':
    #     #
    # elif command == 'deauthorize':
    #     #do
    # elif command == 'exit':

    else:
        print("Unknown Option Selected!")

def isAdmin():
    return user_id['user']=='admin'

def setPassword(newPass):
    currentUser=user_id['user']
    if (os.path.exists(usersFile)):
        for line in fileinput.input([usersFile], inplace=True):
            if line.strip().startswith(currentUser):
                 line = generateSecPass(currentUser,newPass)
            sys.stdout.write(line)
    logging.info('SUCCESS: %s','Your password has been reset successfully.',extra=user_id)

def generateSecPass(user,password):
    # generate new salt, and hash a password
    hash = pbkdf2_sha512.encrypt(password,rounds=10000)
    # pbkdf2_sha512.encrypt returns a string in this format:
    # '$pbkdf2-sha512$10000$rounds=10000$salt$hashed-password'
    # So we need to change the fromat to '$6$salt$hashed-password'
    securedPassword = re.sub('\$pbkdf2-sha512\$10000\$', '', hash)
    dateUpdate = dt.datetime.today().strftime("%m/%d/%Y")
    record = ''+user+':$6$'+securedPassword+':'+dateUpdate+'\n'
    return record

def addFileEntry(file_name,integrity_value,code_salt,owner,authorized_users):
    f = open(filesDB, 'a')
    record = file_name+':'+integrity_value+':'+code_salt+':'+owner+':'+authorized_users
    f.write(record)
    f.close()

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def encrypt_file(file_path, file_pass):
    key=sha256(str(file_pass).encode('utf-8')).digest()
    file_name=os.path.basename(file_path)
    if (not os.path.exists(file_path)):
        logging.error('FAILURE: %s', ('The file %s does not exist.'%file_path), extra=user_id)
    else:
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = encrypt(plaintext, key)
        try:
            with open(os.path.join(home+'/data',file_name), 'wb') as outfile:
                outfile.write(enc)
            logging.info('SUCCESS: %s',('The file %s has been encrypted successfully.'%file_name),extra=user_id)
        except IOError:
            logging.error('FAILURE: %s',('The file %s does not exist.'%outfile), extra=user_id)

def decrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    with open(file_name[:-4], 'wb') as fo:
        fo.write(dec)

if __name__ == '__main__':
    selectMod()
