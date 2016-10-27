import os
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
logging.basicConfig(filename='fileprotector.log', filemode='a',format=FORMAT,level=logging.INFO)
Home_dir = os.getcwd()
usersFile = os.path.join(Home_dir,'users')
filesDB= os.path.join(Home_dir,'files')
user_id={}

def selectMod():
    if (os.path.exists(usersFile)):
        @click.command()
        @click.option('--user', help='username')
        @click.option('--password',hide_input=True,
              help='Enter a password')
        @click.option('--home', help='set home directory')
        def doAuthi(user, password,home):
            if home is not None:
                global Home_dir
                Home_dir = home
            user_id['user']=user
            if(authi(user,password)):
                logging.info('SUCCESS: %s','You are successfully logged in.',extra=user_id)
                request=input()
                while(True):
                    commandOpt(request)
                    request=input()
            else:
                logging.error('FAILURE: %s', 'The username or password you entered is incorrect.', extra=user_id)
                exit()
        doAuthi()
    #Create Admin if users.file doesn't exist.
    else:
        @click.command()
        @click.option('--password', prompt=True, hide_input=True,
              confirmation_prompt=True,  help='Enter a password')
        @click.option('--home', help='set home directory')
        def createAdmin(password,home):
            if home is not None:
                global Home_dir
                Home_dir = home
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
        usersfile = open(usersFile, 'a')
        record = generateSecPass(user,password)
        usersfile.write(record)
        usersfile.close()

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

    elif command == 'decrypt':
        arg=request.split(" ")
        decrypt_file(arg[1], arg[2],arg[3])
    elif command == 'authorize':
        arg=request.split(" ")
        authorizeUser(arg[1],arg[2])
    elif command == 'deauthorize':
        arg=request.split(" ")
        deauthorizeUser(arg[1],arg[2])
    elif command == 'exit':
        exit()
    else:
        print("Command not found")

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

def addFileEntry(file_name,integrity_value,code_salt,authorized_users):
    owner=user_id['user']
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
    KEY_SIZE=16
    DERIVATION_ROUNDS=10000
    salt =Random.new().read(16).hex()
    derivedKey = file_pass+salt
    derivedKey = sha256(derivedKey.encode('utf-8')).digest()
    for i in range(1,DERIVATION_ROUNDS):
        derivedKey = sha256(derivedKey).digest()
    derivedKey = derivedKey[:KEY_SIZE]
    file_name=os.path.basename(file_path)
    if (not os.path.exists(file_path)):
        logging.error('FAILURE: %s', ('The file %s does not exist.'%file_name), extra=user_id)
    else:
        integrity_value= compute_integrity(file_path)
        with open(file_path, 'rb') as fo:
            plaintext = fo.read()
        enc = encrypt(plaintext, derivedKey)
        try:
            os.makedirs(os.path.dirname(os.path.join(Home_dir+'/data',file_name)), exist_ok=True)
            with open(os.path.join(Home_dir+'/data',file_name), 'wb') as outfile:
                outfile.write(enc)
            logging.info('SUCCESS: %s',('The file %s has been encrypted successfully.'%file_name),extra=user_id)
            addFileEntry(file_name,integrity_value,salt,'')
        except IOError:
            logging.error('FAILURE: %s',('Could not open the outfile %s does not exist.'%file_name), extra=user_id)

def decrypt_file(secure_file,orig_file, file_pass):
    (foundFile,authoUser)= lookupFile(secure_file)
    if(foundFile and authoUser):
        KEY_SIZE=16
        DERIVATION_ROUNDS=10000
        (file_integV,salt) = extract_integValue_salt(secure_file)
        derivedKey = file_pass+salt
        derivedKey = sha256(derivedKey.encode('utf-8')).digest()
        for i in range(1,DERIVATION_ROUNDS):
            derivedKey = sha256(derivedKey).digest()
        derivedKey = derivedKey[:KEY_SIZE]
        try:
            with open(os.path.join(Home_dir+'/data',secure_file), 'rb') as fo:
                ciphertext = fo.read()
            dec = decrypt(ciphertext, derivedKey)
        except IOError:
            logging.error('FAILURE: %s',('The file %s does not exist.'%secure_file), extra=user_id)
        try:
            #The decrypted file has the same name as the secure_file
            with open(secure_file, 'wb') as fo:
                fo.write(dec)
        except IOError:
            logging.error('FAILURE: %s',('The file %s does not exist.'%secure_file), extra=user_id)
        integV_decryp = compute_integrity(secure_file)
        if(integV_decryp == file_integV):
            logging.info('SUCCESS: %s',('The file %s has been encrypted successfully.'%secure_file),extra=user_id)
        else:
            os.remove(secure_file)
            logging.error('FAILURE: %s',('Could not decrypt the file %s (it is corrupted OR the code was incorrect).'%secure_file), extra=user_id)


def compute_integrity(file_path):
    file_name= os.path.basename(file_path)
    BLOCKSIZE = 65536
    hasher = sha256()
    with open(file_path, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)
    return hasher.hexdigest()

def lookupFile(file_name):
    if os.path.exists(filesDB):
        with open(filesDB, 'r') as f:
            for line in f:
                #check if the file is present in the DB
                if(line.strip().split(":")[0]==file_name):
                    #check if the currentUser is the owner
                    if line.strip().split(":")[3]==user_id['user']:
                        (foundFile,AuthoUser)= (True,True)
                        return (foundFile,AuthoUser)
                        # check if the currentUser is authorized
                    else:
                        for usr in line.strip().split(":")[4].strip().split(','):
                            if(usr==user_id['user']):
                                (foundFile,authoUser)= (True,True)
                                return (foundFile,authoUser)
                        logging.error('Unauthorized: %s',('You are not allowed to access the file %s.'%file_name), extra=user_id)
                        (foundFile,AuthoUser)= (True,False)
                        return (foundFile,AuthoUser)

    logging.error('FAILURE: %s',('The file %s does not exist.'%file_name), extra=user_id)
    (foundFile,AuthoUser)= (False,False)
    return (foundFile,AuthoUser)

def authorizeUser(username, file_name):
        if os.path.exists(filesDB):
            with open(filesDB, 'r') as f:
                for line in f:
                    #check if the file is present in the DB
                    if(line.strip().split(":")[0]==file_name):
                        #check if the currentUser is the owner
                        if line.strip().split(":")[3]==user_id['user']:
                            userExist=False
                            for usr in line.strip().split(":")[4].strip().split(','):
                                # check if the username is already in the authorized list
                                if(usr==username):
                                    userExist=True
                                    break
                            if(not userExist):
                                addAuthoUser(username,file_name)
                        else:
                            logging.error('Unauthorized: %s',('You are not allowed to access the file %s.'%file_name), extra=user_id)
        else:
            logging.error('FAILURE: %s',('The file %s does not exist.'%file_name), extra=user_id)

def deauthorizeUser(username,file_name):
    if os.path.exists(filesDB):
        with open(filesDB, 'r') as f:
            for line in f:
                #check if the file is present in the DB
                if(line.strip().split(":")[0]==file_name):
                    #check if the currentUser is the owner
                    if line.strip().split(":")[3]==user_id['user']:
                        userExist=False
                        for usr in line.strip().split(":")[4].strip().split(','):
                            # check if the username is already in the authorized list
                            if(usr==username):
                                userExist=True
                                break
                        if(userExist):
                            removeAuthoUser(username,file_name)
                    else:
                        logging.error('Unauthorized: %s',('You are not allowed to access the file %s.'%file_name), extra=user_id)
    else:
        logging.error('FAILURE: %s',('The file %s does not exist.'%file_name), extra=user_id)

def addAuthoUser(username,file_name):
    currentUser=user_id['user']
    if (os.path.exists(filesDB)):
        for line in fileinput.input([filesDB], inplace=True):
            if line.strip().startswith(file_name):
                     line = line.rstrip('\n')+username+','
                     sys.stdout.write(line)
        logging.info('SUCCESS: %s',('Allowed %s to access the file %s.'%(username,file_name)),extra=user_id)

def removeAuthoUser(username,file_name):
    currentUser=user_id['user']
    if (os.path.exists(filesDB)):
        for line in fileinput.input([filesDB], inplace=True):
            if line.strip().startswith(file_name):
                line = line.replace((username+','),'')
                sys.stdout.write(line)
        logging.info('SUCCESS: %s',('Remove %s access to the file %s.'%(username,file_name)),extra=user_id)

def extract_integValue_salt(file_name):
    with open(filesDB, 'r') as f:
        for line in f:
            #check if the file is present in the DB
            if(line.strip().split(":")[0]==file_name):
                return (line.strip().split(":")[1],line.strip().split(":")[2])

if __name__ == '__main__':
    selectMod()
