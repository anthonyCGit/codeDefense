"""
Author: Anthony, Team Member 1, Team Member 2
Date: 8-8-22
Description: A program that safely gathers user input and produces password, output, and log files.
"""
import base64
import logging
import sys
import hashlib
import os
import re

# Salt + Hashing: https://nitratine.net/blog/post/how-to-hash-passwords-in-python/

ERROR = "Please try again.\n"
UNEXPECTED_ERROR = "\nAn unexpected error has occurred. Closing..."
LOG_FILE = "logfile.log"
PASS_FILE = "password.txt"

# Verifies the validity of a name string.
# Valid name characters are A-Z, a-z, -, and '. Any - or ' must be followed by a letter.
# The first character must be capitalized while the rest are lower case.
# Takes in a string, str: The string to verify.
# Returns whether the string is a valid name.
def validNameStr(str):
    p = re.compile('^[A-Z][a-z]*([\'-][a-z]+)*$')
    return p.match(str)

# Verifies the validity of an integer as a string.
# integers are within a standard 4 byte int range.
# Takes in a string, str: The string to verify.
# Returns whether the string is a valid integer.
def validIntStr(str):
    p = re.compile('^(-)?[0-9]+$')

    return p.match(str)

# Verifies the validity of a filename.
# Valid filename characters are A-Z, a-z, 0-9, and any of the following: `~!@#$%^&() _=+[]{};',.-
# The filename must end in .txt
# The string, str, The string to verify.
# Returns whether the string is a valid filename.
def validFilenameStr(str):
    p = re.compile('[\\/:*?\\"<>|]')
    if not p.match(str):
        p = re.compile('^[A-Za-z0-9`~!@#$%^&()_ =+\[\]\{\};\',.-]+(\.txt)$')
        return bool(p.match(str)) & (len(str) >= 5) & (len(str) <= 50)
    else:
        return False

# Verifies the validity of a password.
# Valid password characters are A-Z, a-z, 0-9, and any of the following: `~!@#$%^&()_ =+.-
# The password needs at least one capital letter, one lowercase letter, one number, and one valid symbol.
# The password must be from 8 to 50 characters in length.
# The string, str, The string to verify.
# Returns whether the string is a valid password.
def validPasswordStr(str):
    p = re.compile("^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[`~!@#$%^&()_ =+.-])" +
                   "([A-Za-z0-9`~!@#$%^&()_ =+.-]{8,50})$")
    return p.match(str)

# Generates a new salt to be used in a hash function.
# Returns the salt.
def generateSalt():
    return os.urandom(32)

# Generates an encrypted password using the SHA-512 hashing algorithm and a salt.
# password: The password string to hash.
# salt: The salt to use.
# Returns the hashed password.
def generateHashedPassword(str, salt):
    key = hashlib.pbkdf2_hmac('sha256', str.encode('utf-8'), salt, 100000, dklen=128)
    return key

# Initializes the logger to be used.
def initializeLogger(func_name):
    logger = logging.getLogger("logfile")
    try:
        # tries to initialize the logger
        logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(LOG_FILE)
        fh.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(asctime)s DefendPython ' + func_name + ' \n%(levelname)s : %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        logger.addHandler(fh)
        logger.addHandler(ch)
    except IOError as e:
        sys.exit(UNEXPECTED_ERROR)
        logger.info(e)
    return logger

# Prompts the user for a valid name
# prompt - the text used in input statement, either first or last name
# returns the name string once it is found to be valid
def getName(prompt):
    name = ""
    func_name = sys._getframe().f_code.co_name
    logger = initializeLogger(func_name)
    valid = False
    while not valid:
        print('Valid name characters are A-Z, a-z, -, and \'. Any - or \' must be followed by a letter.')
        print('The first character must be capitalized while the rest are lower case.')
        name = input('Enter your ' + prompt + ' name: ')
        valid = validNameStr(name)
        if not valid:
            print(ERROR)
            logger.info("Invalid Name Entered")

    return name

# Prompts the user for a valid Integer
# prompt - the text used in input statement when asking for user input
# returns the int once it is found to be valid
def getInt(prompt):
    num = 0
    valid = False
    func_name = sys._getframe().f_code.co_name
    logger = initializeLogger(func_name)
    while not valid:
        num = input('Enter a ' + prompt + ' 4-byte integer: ')
        valid = validIntStr(num)

        if not valid:
            print(ERROR)
            logger.info("Invalid Integer Entered")
        elif int(num) > 2147483647 or int(num) < -2147483648:
            valid = False
            print(ERROR)
            logger.info("Invalid Integer Entered")

    return num

# Prompts the user for a valid file name
# prompt - the text used in input statement when asking for user input
# returns the file name once it is found to be valid
def getFilename(prompt):
    filename = ""
    valid = False
    func_name = sys._getframe().f_code.co_name
    logger = initializeLogger(func_name)
    while not valid:
        print('Valid filename characters are A-Z, a-z, 0-9, and any of the following: `~!@#$%^&() _=+[]{};\',.-')
        print('Invalid characters: \\/:*?\"<>|')
        print('The file extension must be \".txt\".')
        print('Filename must be from 5 to 260 characters.')
        print('The file must exist in the current directory.')
        filename = input("Enter your " + prompt + " file: ")
        valid = validFilenameStr(filename)
        if not valid:
            print(ERROR)
            logger.info("Invalid Filename Entered")

    return filename

# Prompts the user for a valid password
# prompt - the text used in input statement when asking for user input
# returns the password once it is found to be valid
def getPassword():
    password = ""
    valid = False
    func_name = sys._getframe().f_code.co_name
    logger = initializeLogger(func_name)
    while not valid:
        print('Valid password characters are A-Z, a-z, 0-9, and any of the following: `~!@#$%^&()_ =+.-')
        print('It must have: ')
        print('- At least one capital letter')
        print('- At least one lower case letter')
        print('- At least one number')
        print('- At least one valid symbol')
        print('- A length from 8 to 50 characters')
        password = input('Enter your password: ')
        valid = validPasswordStr(password)
        if not valid:
            print(ERROR)
            logger.info("Invalid Password Entered")

    return password

# Creates a password file, storing the salt and hashed password.
def createPasswordFile():
    func_name = sys._getframe().f_code.co_name
    logger = initializeLogger(func_name)
    salt = generateSalt()
    password = getPassword()
    hashed_pw = generateHashedPassword(password, salt)

    try:
        bw = open(PASS_FILE, "w")
        salt_enc = base64.b64encode(salt)
        bw.write(salt_enc.decode('utf-8') + '\n')
        pw_enc = base64.b64encode(hashed_pw)
        bw.write(pw_enc.decode('utf-8'))
    except IOError as e:
        print(UNEXPECTED_ERROR)
        logger.info(e)

# Gets the stored salt and hashed password from the password file.
# Returns variable salt string and hashedPassword string
def getStoredPassword():
    func_name = sys._getframe().f_code.co_name
    logger = initializeLogger(func_name)
    try:
        scanner = open(PASS_FILE, 'r')
        salt = scanner.readline()
        pw = scanner.readline()
    except FileNotFoundError as e:
        print(UNEXPECTED_ERROR)
        logger.info(e)
    return salt, pw

# Prompts the user to reenter and verify their password.
def reenterPassword():
    func_name = sys._getframe().f_code.co_name
    logger = initializeLogger(func_name)
    salt, pw = getStoredPassword()
    salt = salt.encode('utf-8')
    pw = pw.encode('utf-8')
    valid = False
    while not valid:
        password = input("Reenter your password: ")
        valid = validPasswordStr(password)
        if not valid:
            print(ERROR)
            logger.info("Invalid Password Validation: Format")
        else:
            hashed_pw = generateHashedPassword(password, base64.b64decode(salt))
            valid = (base64.b64encode(hashed_pw) == pw)
            if not valid:
                print(ERROR)
                logger.info("Invalid Password Validation: Verification")

# Creates an output file of a specified name containing the user's first name, last name, 2 integers, integer sum,
# integer product, and specified input file contents.
# outputFilename: The name of the output file to create.
# inputFile: The input file to read from.
# firstName: The user's first name.
# lastName: The user's last name.
# firstInt: The first integer.
# secondInt: The second integer.
def createOutputFile(outputFileName, inputFile, firstName, lastName, firstInt, secondInt):
    func_name = sys._getframe().f_code.co_name
    logger = initializeLogger(func_name)
    try:
        bw = open(outputFileName, "w")
        text = "First name: " + firstName + "\n"
        print(text, end="")
        bw.write(text)

        text = "Last name: " + lastName + "\n"
        print(text, end="")
        bw.write(text)

        text = "First Integer: " + firstInt + "\n"
        print(text, end="")
        bw.write(text)

        text = "Second Integer: " + secondInt + "\n"
        print(text, end="")
        bw.write(text)

        num = int(firstInt) + int(secondInt)
        text = "Sum: " + str(num) + "\n"
        print(text, end="")
        bw.write(text)

        num = int(firstInt) * int(secondInt)
        text = "Product: " + str(num) + "\n"
        print(text, end="")
        bw.write(text)

        text = "Input File Contents:\n"
        print(text, end="")
        bw.write(text)

        for line in inputFile:
            bw.write(line)
            print(line, end="")

    except IOError as e:
        print(UNEXPECTED_ERROR)
        logger.info(e)

# Prompts for, processes, and displays user input.
def main():
    func_name = sys._getframe().f_code.co_name
    logger = initializeLogger(func_name)
    print('------------ENTER YOUR NAME------------')
    print('===FIRST NAME===')
    firstName = getName("first")
    print()
    print('===LAST NAME===')
    lastName = getName("last")
    print()

    print('------------ENTER YOUR INTEGERS------------')
    print('===FIRST INTEGER===')
    firstInt = getInt("first")
    print()
    print('===SECOND INTEGER===')
    secondInt = getInt("second")
    print()

    print('------------ENTER YOUR FILES------------')
    # file verification
    print('===INPUT FILE===')
    inputFileName = ""
    while True:
        inputFileName = getFilename("input")
        if os.path.exists(inputFileName):
            break
        else:
            print("Ensure file exists.")
            print(ERROR)

    inputFile = open(inputFileName, "r")
    print('===OUTPUT FILE===')
    outputFileName = ""
    loop = True
    while loop:
        outputFileName = getFilename("output")
        if inputFileName == outputFileName:
            print("Ensure input and output files are different.")
            print(ERROR)
        else:
            loop = False

    print()
    print('------------ENTER YOUR PASSWORD------------')
    print('===CREATE PASSWORD===')
    createPasswordFile()
    print()
    print('===REENTER PASSWORD===')
    reenterPassword();
    print()

    print('------------FILE OUTPUT------------')
    createOutputFile(outputFileName, inputFile, firstName, lastName, firstInt, secondInt)
    quit()

# Runs Main
if __name__ == '__main__':
    main()