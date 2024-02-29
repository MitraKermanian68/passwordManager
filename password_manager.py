from cryptography.fernet import Fernet
import os
# import bcrypt

# # Generate a random salt
# salt = bcrypt.gensalt()

# # Hash a password with the salt
# hashed_password = bcrypt.hashpw('my_password'.encode('utf-8'), salt)

# # Now you can securely store the hashed_password in your database

def write_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:#wb = writes in bytes
        key_file.write(key)
def load_key():
    file = open("key.key", "rb")
    key = file.read()
    file.close()
    return key

master_pwd = input("what is your master password? ")
key = load_key() + master_pwd.encode() #encode in bytes
fer = Fernet(key)



# def view():
#     with open("passwords.txt", "r") as f:
#         for line in f.readlines():
#             data = line.rstrip()
#             user, passw = data.split("|")
#             print("Username:", user, "| Password:", fer.decrypt(passw.encode()).decode())

def view():
    if not os.path.exists("passwords.txt"):
        print("File does not exist.")
        return

    with open("passwords.txt", "r") as f:
        lines = f.readlines()

    if not lines:
        print("File is empty.")
        return

    for line in lines:
        data = line.rstrip()
        if "|" not in data:
            print("Invalid line:", data)
            continue

        user, passw = data.split("|")
        try:
            print("Username:", user, "| Password:", fer.decrypt(passw.encode()).decode())
        except Exception as e:
            print("Error decrypting password for user", user, ":", str(e))

def add():
    name = input("Account Name: ")
    pwd = input("Password: ")

    with open("passwords.txt", "a") as f:
        f.write(name + " | " + fer.encrypt(pwd.encode()).decode() + "\n")

while True:
    mode = input("Would you like to add a new password or view existing ones (view/add), type 'q' to quit? ").lower()
    if mode == "q":
        break
    elif mode == "view":
        view()
    elif mode == "add":
        add()
    else:
        print("invalid mode")
        continue

# Assume 'user_password' is the password entered by the user, and 'stored_password' is the hashed password retrieved from the database
# if bcrypt.checkpw(master_pwd.encode('utf-8'), hashed_password):
#     print("Password is correct")
# else:
#     print("Password is incorrect")