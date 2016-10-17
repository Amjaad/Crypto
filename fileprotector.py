import os
import click
import datetime as dt
from passlib.hash import sha512_crypt
import re
# """ Admin Mode
# If the users file is present, then admin username & password must have be supplied.
#  """

def selectMod():
    print(os.path.exists('users'))
    if (os.path.exists('users')):
        @click.command()
        @click.option('--user', help='username')
        @click.option('--password',hide_input=True,
              help='Enter a password')
        #This function should check if
        def doAuthi(user, password):
            click.echo('Hello %s!' % user)
            if(authi(user,password)):
                click.echo("log success")
            else:
                #log failuer
                click.echo("log failuer")
                exit()
        doAuthi()
    #Create Admin if users.file doesn't exist.
    else:
        @click.command()
        @click.option('--password', prompt=True, hide_input=True,
              confirmation_prompt=True,  help='Enter a password')
        def createAdmin(password):
            print(wrong)
            # addEntity('admin',password)
        createAdmin()
        exit()


def authi(user, password):
    usersFile = "users"
    with open(usersFile, "r") as f:
        rows = (line.strip().split(":") for line in f)
        print(rows)
        records = [row for row in rows if row[0] == user]

    hash = records and records[0][1]
    print(hash)
    return sha512_crypt.verify(password, hash)

def addEntity(user,password):
    # generate new salt, and hash a password
    hash = sha512_crypt.encrypt(password,rounds=10000)
    # sha512_crypt.encrypt returns a string in this format:
    #    '$6$rounds=10000$salt$hashed-password'
    # So we change the fromat to '$6$salt$hashed-password'
    securedPassword = re.sub('rounds=10000\$', '', hash)
    dateUpdate = dt.datetime.today().strftime("%m/%d/%Y")
    usersFile = open('users', 'w')
    record = ''+user+':'+securedPassword+':'+dateUpdate+'\n'
    usersFile.write(record)
    usersFile.close()


if __name__ == '__main__':
    selectMod()
