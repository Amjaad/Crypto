## MyCrypto
This is a basic file security system that allows authorized users to encrypt and decrypt files while ensuring that the files are not altered while encrypted. 

## Installation
### Requirements

* A Unix-like operating system (eg. Debian, CentOS, Mac OS X, etc.).

* Python version 3.x
* Use **pip3 install** to get the following libs:
	* hashlib
	* passlib
	* click
	* Crypto.Cipher
	* Crypto
	* logging

  

## Known Issues
If you want to specifiy the home directory, then you need to pass the directory to the home option (--home=directory-path) **in the initialization mode** and when you **login**. If you don't specify the home dirctory when you login, the system may not use it. 

## Security Flaws
* The system does not require the minimum password length to be greater than 8 characters. A password like '123' is accepted by the system. This means if the users pick a bad password with low entropy, their accounts might get hacked without even knowing it. 

* The system does not require new users to reset their passwords after their accounts have been created by the admin. 
So, if the new users don't reset their password the first time they login, the admin can access their account.

* User session doesn't expire. If the user leaves the system running without logging out, the account can be accessed by others.     

##Future Improvements 
   
While MyCrypto v2 is still under development, we would like to let our users know that we are working to fix the security flaws in the system.
  
  What you should expect to see in MyCrypto v2?
  
  * The minimum password length to be greater than 13 characters. The system will compute the entropy for the password the user enters when creating the account. If the password doesn't have at least 80 bits of entropy, It won't be accepted and the user will be asked to choose another password.
  * The systems will not allow the new users to use their account before changing their password. 
  *  User session will expire after 2 hours of not being used.
  *  More advance encryption algorithms will be added. 
  

