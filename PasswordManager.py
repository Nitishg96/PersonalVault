#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#version 2.1
#Autor: Nitish Garg 
#Date: 04.08.2021
import random
import string
import re
from cryptography.fernet import Fernet
import getpass
import os
import pathlib
import sys
import time
import clipboard
import shutil

s = os.getcwd()
path = s.replace('\\', '/')

class total_security:
    
    def __init__(self, name, general_password):
        
        self.name = name
        self.general_password = general_password
        
    def login(self):
        
        try:
            
            website = ''
        
            if(os.path.isfile(self.name +"/" +self.name + "_"+ website+ "secret.key")):
            
                f = open(self.name +"/" +self.name + "secret.txt", "rt")
                message = f.read().rstrip('\n')
                f.close()
                password1 = self.decryption(message = message.encode(),website = website)

                if(self.general_password == password1.decode()):
                    print("Login successful")
                    return True
                else:
                    print("Wrong password")
                    return False
            else: 
                print("Not Registered. Kindly register first")
                return False
        except:
            print("Unknown error contact admin")
    def register(self):
        
        website = ''
        try:
        	pathlib.Path( path +'/' + self.name).mkdir(parents=True, exist_ok=False)

            hide_path = s + "\\" +self.name

            os.system("attrib +h +s " + hide_path)
            #pathlib.Path(path + '/' + self.name).mkdir(parents=True, exist_ok=False)
            self.encrypt_key(website)
            password = self.encryption(message = self.general_password, website = website)
            
            f = open(self.name +"/" +self.name + "secret.txt", "a")
            f.write(password.decode())
            f.close()
            print("Thank you for registering \n Kindly login again to continue")
        
        except: 
            print("username already exist or Wrong Directory")
        

    def save_password(self,website, email, password = "None"):     #delration of save passsword
        
        try:
            f = open(self.name +"/" +self.name + ".txt", "a")                           #opening a text file in which we want to save all inputs
            f.write(website + ';' + email + ";") #printing all those in it
            f.write(password.decode())
            f.write("\n")
            f.close()  #closing text file
            print("Password saved successfully")
        except: print("Error in saving password \n try again later")
    
    def genrate_password(self,password_length = 12):                    #declared genrate function
        
        try:
            words = string.ascii_letters + string.digits + string.punctuation#choosing random variables
            #password_length = int(input("what is the password length: "))#length of password we want
            empty_list = []                                       #list to save password after every circle of for loop
            for password in range(0, password_length):            #loop for making limit of length
                empty_list.append(random.choice(words))           #choosing random variable and putting it in list
                password = "".join(empty_list)                    #converting list into string
                #save_password = True                             #making it save
            return password
        except: print("Error in generating Passowrd. \n Kindly try again later")

    def search_password(self,website):
        
        try:

            pdata = []
            pattern = re.compile(website, re.IGNORECASE)  # Compile a case-insensitive regex
            with open (self.name +"/" +self.name + '.txt', 'rt') as myfile:    
                for line in myfile:
                    if pattern.search(line) != None:      # If a match is found 
                        pdata.append(line.rstrip('\n').split(';'))
            return pdata
        except: return "Error in Searching"

    def save_website(self):

        try:

            wdata = []

            with open (self.name +"/" +self.name + '.txt', 'rt') as f:
                wdata=[line.split(";")[0] for line in f]

            return wdata

        except:
            print("Kindly ignore if you are new user else contact Admin.")


    def delete_password(self,linenum):

        try:

            with open(self.name +"/" +self.name + '.txt', 'r') as read_file:
                lines = read_file.readlines()

            currentline = 1
            with open(self.name +"/" +self.name + '.txt', 'w') as write_file:
                for line in lines:
                    if(currentline == linenum):
                        pass
                    else:
                        write_file.write(line)

                    currentline +=1
            print("Directory Updated")
            #os.remove(self.name +"/" +self.name + "_"+ website+ "secret.key")
        except:
            print("Erorr in deleting. Contact Admin")


    
    def encrypt_key(self,website):
        
        key = Fernet.generate_key() 
        with open(self.name +"/" +self.name + "_"+ website+ "secret.key", "wb") as key_file:
            key_file.write(key)
    
    def load_key(self, website):
        if(os.path.isfile(self.name +"/" +self.name + "_"+ website+ "secret.key")):
            
            return open(self.name +"/" +self.name + "_"+ website+ "secret.key", "rb").read()
        else: 
            print("File not found")
            quit(abs)
    
    def encryption(self,message,website):
        
        key = self.load_key(website)
        encoded_message = message.encode()
        f = Fernet(key)
        encMessage = f.encrypt(encoded_message)
        
        return encMessage
    
    def decryption(self,message,website):
        
        key = self.load_key(website)
        f = Fernet(key)
        decMessage = f.decrypt(message)
        
        return decMessage

    def delete_account(self):
    	hide_path = s + "\\" +self.name
    	os.system("attrib -r -h -s " + hide_path)
    	shutil.rmtree(hide_path)


    def line_count(self):
    	try:
    		file = open(self.name +"/" +self.name + '.txt', 'r')
    		nonempty_lines = [line.strip("\n") for line in file if line != "\n"]
    		file.close()
    		line_count = len(nonempty_lines)
    		return str(line_count)
    	except:
    		line_count = 0
    		return str(line_count)

if __name__ == "__main__":
    
    while (1):
        try:
            print("\n Welcome to your Personal Password Manager \n \n")
            print("Enter Login Details or Press ctrl-C to exit")
            p1 = total_security(name = input("login id: "),general_password = getpass.getpass('Password:'))
            if(not p1.login()):
                print("Options: \n 1. Login \n 2. Register \n ")
                argument = int(input("Enter choice number: "))

                if argument == 1:

                    continue

                elif argument == 2:

                    name = input("Enter unique username without space: ")
                    user_password = getpass.getpass('Password: ')
                    user_repeat_password = getpass.getpass('Repeat Password: ')
                    if user_password == user_repeat_password:
                        p1 = total_security(name, user_password)
                        p1.register()
                        p1.login()
                    else:
                        print("Password not matched. Kindly try again")
                    continue

                else:
                    print("Wrong choice. \n Program Exiting")
                    break


        except:
                print("Unknown Error. Contact Admin")
                break

        while (1):

            print("Options: \n 1. save password \n 2. Generate password \n 3. Search Password \n 4. Delete Password \n 5. log out \n Press 7 to delete existing account")
    
            argument = int(input("Enter choice number: "))
    

            if argument == 1:
                web = p1.line_count() + input(" unique website/source name : ")  #site we want to save
                
                '''
                wdata = p1.save_website()
                if(wdata != None):
                	web = p1.line_count() + web
                	for data in wdata: 
                		if data == web:
                			print("website already exist. Modifying name automatically")
                			web = web + "1"
                			break
				'''
                mail = input("email/username : ")                              #mail we want save
                pas = getpass.getpass('Password :')                         #password we want to save
                p1.encrypt_key(web + mail[1:5])
                password1 = p1.encryption(message = pas, website = web + mail[1:5])
                p1.save_password(website = web,email = mail,password = password1)

            elif argument == 2:
                password_length = int(input("Select password length: "))#length of password we want
                password = p1.genrate_password(password_length)
                print("password:",password)
                save_generated_password = input("Press 1 to save this password and press 0 to exit")
                if(save_generated_password =="1"):
                
                    web = p1.line_count() + input(" unique website/source name : ")
                    '''wdata = p1.save_website()

                    if(wdata != None):

                        for data in wdata:

                            if data == web:
                                print("website already exist. Modifying name automatically")
                                web = web + "1"
                                break'''


                    mail = input("email/username : ")                          #mail we want save
                    p1.encrypt_key(website = web+ mail[1:5])
                    password1 = p1.encryption(message = password, website = web+ mail[1:5])
                    p1.save_password(website = web,email = mail,password = password1)
        
                else:
                    print("Password generated successfully but not saved")
                
            elif argument == 3:

                wdata = p1.save_website()
                for count,data in enumerate(wdata):
                    print(count+1, ":", data)

                inp = int(input("Enter number for which website you want a Password: "))

                data1 = []
                
                try:
                    web = wdata[inp-1]
                    print(web)
                except: 
                    print("Please enter the correct option")
                    continue

                data = p1.search_password(website = web)
            
                if data != data1:
                    for num,item in enumerate(data):
                        #print(data) #optional- for testing purpose only
                        print("\n \n ")
                        print("Entry:", num+1)
                        print("website:",item[0])
                        print("email:", item[1])
                        mail = item[1]
                        decrypt_pass = item[2].encode()
                        password = p1.decryption(message = decrypt_pass, website = item[0] + mail[1:5]).decode()
                        clipboard.copy(password)
                        print("Passowrd copied to clipboard")

                        if(input("Press 1 to see password") == '1'):

                            print("password:",password,end='')
                            sys.stdout.flush()
                            time.sleep(2)
                            print("\r password:",''.join('#' for i in range(len(password))))

                        print("\n \n ")
                else:
                    print("Details not found")

            elif argument ==4:

                wdata = p1.save_website()
                for count,data in enumerate(wdata):
                    print(count+1, ":", data)

                inp = int(input("Enter number for which website you want to delete entry: "))

                p1.delete_password(inp) 
            
            elif argument == 5:
                if(input("Do you really want to log out?[y/n]") == "y"):
                    print("Log out Successful")
                    break

            elif argument == 7:

            	print("Login again to delete account")

            	p3 = total_security(name = input("Enter Username: "),general_password = getpass.getpass('Password:'))
            	if(p3.login() & (input("Do you really want to delete account? Press 1 to confirm.")=="1")):

            		p3.delete_account()
            		print("Account Deleted")
            		break

            	else:
            		print("Account not deleted. Try again later")
            		continue

            else:
                print("wrong entry")
                