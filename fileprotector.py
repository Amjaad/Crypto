import os
import sys
import fileinput
import click
import datetime as dt
from passlib.hash import sha512_crypt
from os.path import expanduser
import logging
import re

FORMAT = '%(asctime)-10s %(user)-8s %(message)s'
logging.basicConfig(format=FORMAT,level=logging.INFO)
home = expanduser("~")
user_id={}
def selectMod():
    if (os.path.exists('users')):
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
    usersFile = "users"
    foundUser=False
    with open(usersFile, "r") as f:
                rows = (line.strip().split(":") for line in f)
                records = [row for row in rows if row[0] == user]
                if(len(records)):
                    foundUser=True
    if foundUser:
        securedPass = records and records[0][1]
        hash= securedPass[0:3]+"rounds=10000$"+securedPass[3:]
        return sha512_crypt.verify(password, hash)

def addEntity(user,password):
    if(os.path.exists('users') and not isAdmin()):
        logging.error('UNAUTHORIZED: %s', 'Not allowed because you do not have permission to add a user', extra=user_id)
    elif(usernameExists(user)):
        logging.error('FAILURE: %s', ('Username "%s" already exists.'%user), extra=user_id)
    else:
        usersFile = open('users', 'a')
        record = generateSecPass(user,password)
        usersFile.write(record)
        usersFile.close()

def usernameExists(user):
    usersFile = "users"
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
    elif command == '':
        print("find")
    else:
        print("Unknown Option Selected!")


def isAdmin():
    return user_id['user']=='admin'

def setPassword(newPass):
    currentUser=user_id['user']
    usersFile = "users"
    if (os.path.exists(usersFile)):
        for line in fileinput.input([usersFile], inplace=True):
            if line.strip().startswith(currentUser):
                 line = generateSecPass(currentUser,newPass)
            sys.stdout.write(line)

def generateSecPass(user,password):
    # generate new salt, and hash a password
    hash = sha512_crypt.encrypt(password,rounds=10000)
    # sha512_crypt.encrypt returns a string in this format:
    #    '$6$rounds=10000$salt$hashed-password'
    # So we need to change the fromat to '$6$salt$hashed-password'
    securedPassword = re.sub('rounds=10000\$', '', hash)
    dateUpdate = dt.datetime.today().strftime("%m/%d/%Y")
    record = ''+user+':'+securedPassword+':'+dateUpdate+'\n'
    return record

if __name__ == '__main__':
    selectMod()
