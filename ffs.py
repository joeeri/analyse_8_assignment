import sqlite3
import sys
from sqlite3 import Error
import validator
import logger
import random
import datetime
from getpass import getpass
from user import User
from zipfile import ZipFile


class FurnicorFamilySystem:
    def __init__(self):
        self.connection = None
        self.cursor = None
        self.user = None
        self.insystem = True
        self.logged_in = False
        self.validator = validator.Validator()
        self.logger = logger.Logger()


    def startsystem(self):
        print("--Welcome to the system!--\n")
        try:
            self.connection = sqlite3.connect("family.db")
            self.cursor = self.connection.cursor()
            # print("--Successfully connected to the database!--\n")
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS members
                           (id integer PRIMARY KEY AUTOINCREMENT, membership_id integer UNIQUE, first_name text,
                           last_name text, street text, housenumber text, zipcode text, 
                           city text, email text UNIQUE, phone text, 
                           registration_date datetime default current_timestamp)''')
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS employees
                                       (id integer PRIMARY KEY AUTOINCREMENT, 
                                       username text UNIQUE, password text, first_name text, last_name text,
                                       registration_date datetime default current_timestamp, rights text)''')
        except Error as e:
            print(f"Cannot connect to the database, connection error: {e} \n Please check the error and try again")

    def startloop(self):
        while self.insystem:
            self.login()
            while self.logged_in:
                self.menu()

    def login(self):
        print("--Login Furnicor Family System--\n")
        attemps = 0
        attemps_left = 4 # five attemps
        while not self.logged_in:
            input_username = self.validator.hash(input("Username: ").lower())
            input_password = self.validator.hash(getpass( 'Password: ' ))
            self.cursor.execute("SELECT * FROM employees WHERE username = ? AND password = ?",
                                (input_username, input_password))  # Prevent SQL Injection by using prepared statements
            res_of_user = self.cursor.fetchall()
            if attemps_left == 0:
                self.logger.log("None", "Session is stopped after five wrong login attemps",
                                f"username: {self.validator.unhash(input_username)}", "Yes")
                print("\n-Too many login attemps: session stopped, please try again later-\n")
                self.forceexit()
                break
            if len(res_of_user) > 0:
                self.user = User(res_of_user[0][0], self.validator.unhash(res_of_user[0][1]),
                                 res_of_user[0][6])
                self.logged_in = True
                print("--Login successfully--\n")
                print(f"\n- Welcome to the system {self.user.username}!")
                self.logger.log(self.user.username, "Logged in", f"rights: {self.user.rights}", "No")
            else:
                attemps_left -= 1
                attemps = attemps + 1
                print("Username and password combination doesn't exists, please try again")
                self.logger.log("None", f"Failed login, username: {self.validator.unhash(input_username)}, attempt: {attemps}",
                                "None", "No")

    def logout(self):
        self.logger.log(self.user.username, "Logged out", f"rights: {self.user.rights}", "No")
        print("--Sucessfull logged out--")
        self.logged_in = False
        self.user = None


    def exit(self):
        self.logger.log(self.user.username, "Exit system", f"rights: {self.user.rights}", "No")
        print(f"\n--Bye, hope to see you back soon!--\n")
        self.logout()
        self.insystem = False

    def forceexit(self):
        print(f"\n--Exit--\n")
        self.insystem = False
        self.logged_in = False


    def addmember(self):  # Every input is checked for malicious input
        first_name = last_name = street = housenumber = zip_code = city = email = mobile_phone = membership_id = ""
        adding_member = True
        while adding_member:
            print("\n--Add information to member--")
            while True:
                first_name = input("First name: ")  # First name
                res_first_name_check = self.validator.checkattack(first_name)
                if not res_first_name_check["correct"]:
                    print(res_first_name_check["message"])
                    return {"attack": True, "log": "Malicious input detected: field (first_name) "
                                                   "at function 'addmember'",
                            "add_info": f" while adding new members first name: {first_name}"}
                else:
                    res_first_name_check = self.validator.checkname(first_name)
                    if res_first_name_check["correct"]:
                        break
                    else:
                        print(res_first_name_check["message"])
                        continue
            while True:
                last_name = input("Last name: ")  # Last name
                res_last_name_check = self.validator.checkattack(last_name)
                if not res_last_name_check["correct"]:
                    print(res_last_name_check["message"])
                    return {"attack": True, "log": "Malicious input detected: field (last_name) "
                                                   "at function 'addmember'",
                            "add_info": f" while adding new members last name: {last_name}"}
                else:
                    res_last_name_check = self.validator.checkname(last_name)
                    if res_last_name_check["correct"]:
                        break
                    else:
                        print(res_last_name_check["message"])
                        continue

            while True:
                street = input("Street: ")  # Street
                res_street_check = self.validator.checkattack(street)
                if not res_street_check["correct"]:
                    print(res_street_check["message"])
                    return {"attack": True, "log": "Malicious input detected: field (street) "
                                                   "at 'addmember'",
                            "add_info": f"while adding new members street: {street}"}
                else:
                    res_street_check = self.validator.checkstreet(street)
                    if res_street_check["correct"]:
                        break
                    else:
                        print(res_street_check["message"])
                        continue

            while True:
                housenumber = input("House number: ")  # Housenumber
                res_housenumber_check = self.validator.checkattack(housenumber)
                if not res_housenumber_check["correct"]:
                    print(res_housenumber_check["message"])
                    return {"attack": True, "log": "Malicious input detected: field (housenumber) "
                                                   "at 'addmember'",
                            "add_info": f"while adding new members housenumber: {housenumber}"}
                else:
                    res_housenumber_check = self.validator.checkhousenumber(housenumber)
                    if res_housenumber_check["correct"]:
                        break
                    else:
                        print(res_housenumber_check["message"])
                        continue

            while True:
                zip_code = input("Zipcode [0000AA]: ")  # Postcode
                res_zip_code_check = self.validator.checkattack(zip_code)
                if not res_zip_code_check["correct"]:
                    print(res_zip_code_check["message"])
                    return {"attack": True, "log": "Malicious input detected: field (zip_code) at 'addmember'",
                            "add_info": f"while adding new members zipcode: {zip_code}"}
                else:
                    res_zip_code_check = self.validator.checkzipcode(zip_code)
                    if res_zip_code_check["correct"]:
                        break
                    else:
                        print(res_zip_code_check["message"])
                        continue

            while True:
                city = input(
                    f"{self.validator.cities} \n Choose city by entering it's number (1 - 10): ")  # Stad
                res_city_check = self.validator.validateserver(city)  # If this input is not correct the
                if not res_city_check["correct"]:  # session will be stopped
                    print(res_city_check["message"])
                    return {"attack": True,
                            "log": "Malicious input detected: field (city) at 'addmember'",
                            "add_info": f"while selecting new members city: {city}"}
                break

            while True:
                email = input("Email: ")  # Email
                res_mail_check = self.validator.checkattack(email)
                if not res_mail_check["correct"]:
                    print(res_mail_check["message"])
                    return {"attack": True,
                            "log": "Malicious input detected: field (email) at 'addmember'",
                            "add_info": f"while adding new members email: {email}"}
                else:
                    res_mail_check = self.validator.checkemail(email)
                    if res_mail_check["correct"]:
                        break
                    else:
                        print(res_mail_check["message"])
                        continue

            while True:
                landcode = "+31-6-"
                phonenumber = input("Phone number (mobile_phone) [+31-6-XXXXXXXX]: ")  # Phonenumber
                res_mobile_phone = self.validator.checkattack(phonenumber)
                if not res_mobile_phone["correct"]:
                    print(res_mobile_phone["message"])
                    return {"attack": True, "log": "Malicious input detected: field (mobile_phone) at 'addmember'",
                            "add_info": f"while adding new members phonenumber: {phonenumber}"}
                else:
                    res_mobile_phone = self.validator.checkphonenumber(phonenumber)
                    if res_mobile_phone["correct"]:
                        mobile_phone = landcode + phonenumber
                        break
                    else:
                        print(res_mobile_phone["message"])
                        continue
            while True: # Create a membership_id
                range_start = 10 ** (9 - 1)
                range_end = (10 ** 9) - 1
                num = random.randint(range_start, range_end)  # Create a random 9 digit number, can't start with zero
                result = 0
                hold = num
                while num > 0:  # Counts every digit
                    rem = num % 10
                    result = result + rem
                    num = int(num / 10)
                mod = result % 10  # Calculate the module
                membership_id = hold * 10 + mod  # Adds the module to the membership id
                break
            adding_member = False

        self.cursor.execute(
            "INSERT INTO members(membership_id, first_name, last_name, street, housenumber, zipcode, city, email, phone)"
            " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (membership_id, first_name, last_name, street, housenumber, zip_code, self.validator.cities[city], email, mobile_phone))
        self.connection.commit()
        self.logger.log(self.user.username, "Added member to the database",
                        f" added member: {membership_id}, {first_name} {last_name}", "No")
        print(f"\n--Member {first_name} {last_name} with id: {membership_id}, successfully added to the system--")
        return {"attack": False}

    def editmember(self, member_id):
        first_name = last_name = street = housenumber = zip_code = city = email = mobile_phone = ""
        edit_member = True
        while edit_member:
            print(f"\n--Edit information from member_id: {member_id}--")
            while True:
                first_name = input("First name: ")  # First name
                res_first_name_check = self.validator.checkattack(first_name)
                if not res_first_name_check["correct"]:
                    print(res_first_name_check["message"])
                    return {"attack": True, "log": "Malicious input detected: field (first_name) "
                                                   "at function 'editmember'",
                            "add_info": f" while adding editing members first name: {first_name}"}
                else:
                    res_first_name_check = self.validator.checkname(first_name)
                    if res_first_name_check["correct"]:
                        break
                    else:
                        print(res_first_name_check["message"])
                        continue
            while True:
                last_name = input("Last name: ")  # Last name
                res_last_name_check = self.validator.checkattack(last_name)
                if not res_last_name_check["correct"]:
                    print(res_last_name_check["message"])
                    return {"attack": True, "log": "Malicious input detected: field (last_name) "
                                                   "at function 'editmember'",
                            "add_info": f" while adding editing members last name: {last_name}"}
                else:
                    res_last_name_check = self.validator.checkname(last_name)
                    if res_last_name_check["correct"]:
                        break
                    else:
                        print(res_last_name_check["message"])
                        continue
            while True:
                street = input("Street: ")  # Street
                res_street_check = self.validator.checkattack(street)
                if not res_street_check["correct"]:
                    print(res_street_check["message"])
                    return {"attack": True, "log": "Malicious input detected: field (street) "
                                                   "at 'editmember'",
                            "add_info": f"while adding editing members street: {street}"}
                else:
                    res_street_check = self.validator.checkstreet(street)
                    if res_street_check["correct"]:
                        break
                    else:
                        print(res_street_check["message"])
                        continue
            while True:
                housenumber = input("House number: ")  # Housenumber
                res_housenumber_check = self.validator.checkattack(housenumber)
                if not res_housenumber_check["correct"]:
                    print(res_housenumber_check["message"])
                    return {"attack": True, "log": "Malicious input detected: field (housenumber) "
                                                   "at 'editmember'",
                            "add_info": f"while editing members housenumber: {housenumber}"}
                else:
                    res_housenumber_check = self.validator.checkhousenumber(housenumber)
                    if res_housenumber_check["correct"]:
                        break
                    else:
                        print(res_housenumber_check["message"])
                        continue
            while True:
                zip_code = input("Zipcode [0000AA]: ")  # Postcode
                res_zip_code_check = self.validator.checkattack(zip_code)
                if not res_zip_code_check["correct"]:
                    print(res_zip_code_check["message"])
                    return {"attack": True, "log": "Malicious input detected: field (zip_code) at 'editmember'",
                            "add_info": f"while editing members zipcode: {zip_code}"}
                else:
                    res_zip_code_check = self.validator.checkzipcode(zip_code)
                    if res_zip_code_check["correct"]:
                        break
                    else:
                        print(res_zip_code_check["message"])
                        continue
            while True:
                city = input(
                    f"Choose city by entering it's number (1 - 10): \n   {self.validator.cities}")  # Stad
                res_city_check = self.validator.validateserver(city)  # If this input is not correct the
                if not res_city_check["correct"]:  # session will be stopped
                    print(res_city_check["message"])
                    return {"attack": True,
                            "log": "Malicious input detected: field (city) at 'editmember'",
                            "add_info": f"while editing members city: {city}"}
                break
            while True:
                email = input("Email: ")  # Email
                res_mail_check = self.validator.checkattack(email)
                if not res_mail_check["correct"]:
                    print(res_mail_check["message"])
                    return {"attack": True,
                            "log": "Malicious input detected: field (email) at 'editmember'",
                            "add_info": f"while editing members email: {email}"}
                else:
                    res_mail_check = self.validator.checkemail(email)
                    if res_mail_check["correct"]:
                        break
                    else:
                        print(res_mail_check["message"])
                        continue
            while True:
                landcode = "+31-6-"
                phonenumber = input("Phone number (mobile_phone) [+31-6-XXXXXXXX]: ")  # Phonenumber
                res_mobile_phone = self.validator.checkattack(phonenumber)
                if not res_mobile_phone["correct"]:
                    print(res_mobile_phone["message"])
                    return {"attack": True, "log": "Malicious input detected: field (mobile_phone) at 'addmember'",
                            "add_info": f"while editing phonenumber: {phonenumber}"}
                else:
                    res_mobile_phone = self.validator.checkphonenumber(phonenumber)
                    if res_mobile_phone["correct"]:
                        mobile_phone = landcode + phonenumber
                        break
                    else:
                        print(res_mobile_phone["message"])
                        continue
            edit_member = False
        self.cursor.execute(
            "UPDATE members set first_name=?, last_name=?, street=?, housenumber=?, zipcode=?, city=?, email=?, phone=? WHERE membership_id=?;",
            (first_name, last_name, street, housenumber, zip_code, self.validator.cities[city], email,
             mobile_phone, member_id))
        self.connection.commit()
        self.logger.log(self.user.username, f"Edited member id: {member_id}",
                        f" edited member: {first_name} {last_name}", "No")
        print(f"--Member: {member_id}, {first_name} {last_name} successfully edited--")
        return {"attack": False}

    def addemployee(self, employee_rights, employee_rights_name):  # Inputs are checked because it's connected to the database
        print(f"Registering new {employee_rights_name}")
        while True:
            input_username = input("Username: ")
            res_input_username = self.validator.checkattack(input_username)
            if not res_input_username["correct"]:
                print(res_input_username["message"])
                return {"attack": True, "log": res_input_username["message"],
                        "add_info": f"while adding new employee username: {input_username}"}
            response = self.validator.checkusername(input_username)  # Check for username
            if not response["correct"]:
                print(response["message"])
                continue
            break

        while True:
            input_password = input("Password: ")
            res_input_password = self.validator.checkattack(input_password)
            if not res_input_password["correct"]:
                print(res_input_password["message"])
                return {"attack": True, "log": res_input_password["message"],
                        "add_info": f"while adding new employee password: {input_password}"}
            response = self.validator.checkpassword(input_password)  # Check for password
            if not response["correct"]:
                print(response["message"])
                continue
            break
        if employee_rights == "2" or employee_rights == "3":
            input_firstname = input("First name: ")
            res_first_name_check = self.validator.checkattack(input_firstname)
            if not res_first_name_check["correct"]:
                print(res_first_name_check["message"])
                return {"attack": True, "log": ("Malicious input detected: field (first_name) "
                                               "at function 'addemployee"),
                        "add_info": f"while adding new employee first_name: {input_firstname}"}
            input_lastname = input("Last name: ")
            res_last_name_check = self.validator.checkattack(input_lastname)
            if not res_last_name_check["correct"]:
                print(res_last_name_check["message"])
                return {"attack": True, "log": ("Malicious input detected: field (last_name) "
                                               "at function 'addemployee"),
                        "add_info": f"while adding new employee first_name: {input_lastname}"}
            hashed_username = self.validator.hash(input_username.lower())  # Hash username & password
            hashed_password = self.validator.hash(input_password)  # before adding to the database
            self.cursor.execute("INSERT INTO employees(username, password, rights, first_name, last_name) VALUES(?, ?, "
                                "?, ?, ?)",
                                (hashed_username, hashed_password, employee_rights, input_firstname, input_lastname))
            self.connection.commit()
        else:
            hashed_username = self.validator.hash(input_username.lower())  # Hash username & password
            hashed_password = self.validator.hash(input_password)  # before adding to the database
            self.cursor.execute("INSERT INTO employees(username, password, rights) VALUES(?, ?, ?)",
                                (hashed_username, hashed_password, employee_rights))
            self.connection.commit()
        print(f"--Employee successfully added with rights {employee_rights} --")
        self.logger.log(self.user.username, "Added to the database", f" added employee: {input_username}", "No")
        return {"attack": False}

    def editemployee(self, employee_id):
        print(f"Editing employee: {employee_id}")
        while True:
            input_username = input("Username: ")
            res_input_username = self.validator.checkattack(input_username)
            if not res_input_username["correct"]:
                print(res_input_username["message"])
                return {"attack": True, "log": res_input_username["message"],
                        "add_info": f"while editing employee's new username: {input_username}"}
            response = self.validator.checkusername(input_username)  # Check for username
            if not response["correct"]:
                print(response["message"])
                continue
            break

        while True:
            input_password = input("Password: ")
            res_input_password = self.validator.checkattack(input_password)
            if not res_input_password["correct"]:
                print(res_input_password["message"])
                return {"attack": True, "log": res_input_password["message"],
                        "add_info": f"while editing employee's new password: {input_password}"}
            response = self.validator.checkpassword(input_password)  # Check for password
            if not response["correct"]:
                print(response["message"])
                continue
            break

        while True:
            right = input(
                f"Choose right by entering it's number (1 or 2): \n   {self.validator.rights}")  # Rights
            res_right_check = self.validator.validateserver(right)  # If this input is not correct the
            if not res_right_check["correct"]:  # session will be stopped
                print(res_right_check["message"])
                return {"attack": True,
                        "log": "Malicious input detected: field (right) at 'editemployee'",
                        "add_info": f"while editing employee's new right: {right}"}
            break

        while True:
            input_firstname = input("First name: ")
            res_first_name_check = self.validator.checkattack(input_firstname)
            if not res_first_name_check["correct"]:
                print(res_first_name_check["message"])
                return {"attack": True, "log": ("Malicious input detected: field (first_name) "
                                                "at function 'editemployee"),
                        "add_info": f"while editing employee's new first_name: {input_firstname}"}
            break
        while True:
            input_lastname = input("Last name: ")
            res_last_name_check = self.validator.checkattack(input_lastname)
            if not res_last_name_check["correct"]:
                print(res_last_name_check["message"])
                return {"attack": True, "log": ("Malicious input detected: field (last_name) "
                                                "at function 'editemployee"),
                        "add_info": f"while editing employee's new first_name: {input_lastname}"}
            break

        hashed_username = self.validator.hash(input_username.lower())  # Hash username & password
        hashed_password = self.validator.hash(input_password)  # before adding to the database
        self.cursor.execute(
                        "UPDATE employees set username=?, password=?, rights=?, first_name=?, last_name=? WHERE id=?;",
            (hashed_username, hashed_password, self.validator.rights[right], input_firstname, input_lastname, employee_id))
        self.connection.commit()
        print(f"\n--Employee {input_username} successfully edited --")
        self.logger.log(self.user.username, "Edited employee", f" edited employee: {input_username}", "No")
        return {"attack": False}


    def menu(self):
        user_in_menu = True
        while user_in_menu:
            if self.user.rights == "1": #superadmin
                print(
                    "\n--OPTIONS--\n"
                    "1: Add a new system administrator\n"
                    "2: Add a new member\n"
                    "3: Add a new advisor\n"
                    "4: Request systemlog\n"
                    "5: Create backup\n"
                    "6: Edit information from a member\n"
                    "7: Delete a member\n"
                    "8: Edit information from a employee (systemadmin or advisor)\n"
                    "9: Delete an employee\n"
                    "10: Update password from an employee\n"
                    "11: List users with rights\n"
                    "12: Search member\n"
                    "13: Log out\n"
                    "14: Exit")
                option = input("Choose option with 1 and 14. Just type the number and hit enter: ")
                if option == "1":
                    res = self.addemployee(2, "systemadmin")
                    if res["attack"]:
                        self.logger.log(self.user.username, res["log"], res["add_info"], "Yes")
                        self.forceexit()
                        break
                elif option == "2":
                    res = self.addmember()
                    if res["attack"]:
                        self.logger.log(self.user.username, res["log"], res["add_info"], "Yes")
                        self.forceexit()
                        break
                elif option == "3":
                    res = self.addemployee(3, "advisor")
                    if res["attack"]:
                        self.logger.log(self.user.username, res["log"], res["add_info"], "Yes")
                        self.forceexit()
                        break
                elif option == "4":
                    self.logger.getlogs()
                    self.logger.log(self.user.username, "Get logs", "None", "No")
                elif option == "5":
                    self.createbackup()
                elif option == "6":
                    print("List of members:")
                    getmembers = self.cursor.execute("SELECT membership_id, first_name, last_name FROM members")
                    listmembers = getmembers.fetchall()
                    showmembers = list()
                    for x in listmembers:
                        print("Membership id:", x[0], "Name:", x[1] ,x[2])
                        showmembers.append(x[0])
                    choosemember = input(f" \n{showmembers} \n"
                                         f"Type the membership id from aboves information of the user who's information needs to be changed: ")
                    try:
                        int(choosemember)
                        res_name_check = self.validator.validatelist(showmembers,
                                                                     int(choosemember))  # If this input is not correct the
                        if not res_name_check["correct"]:  # session will be stopped
                            print(res_name_check["message"])
                            return {"attack": True,
                                    "log": "Malicious input detected: field (membership_id) at 'edit information from employee'",
                                    "add_info": f"while looking up membership_id: {choosemember}"}
                    except ValueError:
                        res_name_string_check = self.validator.checkattack(choosemember)
                        if not res_name_string_check["correct"]:
                            print(res_name_string_check["message"])
                            self.logger.log(self.user.username,
                                    "Malicious input detected: looking for membership_id",
                                    f"try to editing members information, input: {choosemember}", "Yes")
                            self.forceexit()
                            break
                        else:
                            self.logger.log(self.user.username, "Change information member",
                                            f" search for member with wrong input: {choosemember}", "Yes")
                            print("\nThat's not an id, please try again")
                            continue
                    res = self.editmember(choosemember)
                    if res["attack"]:
                        self.logger.log(self.user.username, res["log"], res["add_info"], "Yes")
                        self.forceexit()
                        break
                elif option == "7":
                    getmembers = self.cursor.execute("SELECT membership_id, first_name, last_name FROM members")
                    listmembers = getmembers.fetchall()
                    for x in listmembers:
                        print("ID:", x[0], "Name:", x[1], x[2])
                    choosemember = input("Type the membership id of the member who needs to be deleted: ")
                    try:
                        int(choosemember)
                    except ValueError:
                        self.logger.log(self.user.username, "Delete member",
                                        f" search for deletion member: {choosemember}", "Yes")
                        print("\nThat's not an id, please try again")
                        continue
                    res = self.deletemember(choosemember)
                    if res["attack"]:
                        self.logger.log(self.user.username, res["log"], res["add_info"], "Yes")
                        self.forceexit()
                        break
                elif option == "8":
                    getemployees = self.cursor.execute("SELECT id, username, first_name, last_name, rights FROM employees "
                                                       "WHERE rights = 'systemadmin' OR rights = 'advisor'")
                    listemployees = getemployees.fetchall()
                    for x in listemployees:
                        print("ID:", x[0], "Username:", self.validator.unhash(x[1]),
                              f"Name: {x[2]} {x[3]}", "Right:", x[4])
                    chooseemployee = input("Type the id of the employee who's information needs to be changed: ")
                    try:
                        int(chooseemployee)
                    except ValueError:
                        self.logger.log(self.user.username, "Edit employee",
                                        f" search for editing employee: {chooseemployee}", "Yes")
                        print("\nThat's not an id, please try again")
                        continue
                    res = self.editemployee(chooseemployee)
                    if res["attack"]:
                        self.logger.log(self.user.username, res["log"], res["add_info"], "Yes")
                        self.forceexit()
                        break
                elif option == "9":
                    getemployees = self.cursor.execute("SELECT id, username, first_name, last_name, rights FROM employees "
                                                       "WHERE rights = 'systemadmin' OR rights = 'advisor'")
                    listemployees = getemployees.fetchall()
                    print("Employees:")
                    for x in listemployees:
                        print(f"ID: {x[0]}, Username: {self.validator.unhash(x[1])}, Name: {x[2]} {x[3]}, Right: {x[4]}")
                    chooseemployee = input("Type the ID of the employee who's needs to be deleted: ")
                    try:
                        int(chooseemployee)
                    except ValueError:
                        self.logger.log(self.user.username, "Delete employee",
                                        f" search for deleting employee: {chooseemployee}", "Yes")
                        print("\nThat's not an id, please try again")
                        continue
                    res = self.deleteemployee(chooseemployee)
                    if res["attack"]:
                        self.logger.log(self.user.username, res["log"], res["add_info"], "Yes")
                        self.exit()
                        break
                elif option == "10":
                    getemployees = self.cursor.execute(
                        "SELECT id, username, first_name, last_name, rights FROM employees "
                        "WHERE rights = 'systemadmin' OR rights = 'advisor'")
                    listemployees = getemployees.fetchall()
                    for x in listemployees:
                        print("ID:", x[0], "Username:", self.validator.unhash(x[1]),
                              f"Name: {x[2]} {x[3]}, Right: {x[4]}")
                    chooseemployee = input("Type the id of the employee who's password needs to be updated: ")
                    try:
                        int(chooseemployee)
                    except ValueError:
                        self.logger.log(self.user.username, "Change password",
                                        f" search for employee changes password: {chooseemployee}", "Yes")
                        print("\nThat's not an id, please try again")
                        continue
                    res = self.updatepassword(chooseemployee)
                    if res["attack"]:
                        self.logger.log(self.user.username, res["log"], res["add_info"], "Yes")
                        self.forceexit()
                        break
                elif option == "11":
                    self.listemployeeswithrights()
                elif option == "12":
                    self.searchmember()
                elif option == "13":
                    self.logout()
                    user_in_menu = False
                elif option == "14":
                    self.exit()
                    break
                else:
                    print("Option does not exists. Please choose again with 1, 2, 3 or 4")
                    continue

            elif self.user.rights == "2": #systemadmin
                print(
                    "1: Add a new member\n"
                    "2: Add a new advisor\n"
                    "3: Request systemlog\n"
                    "4: Create backup\n"
                    "5: Edit information from a member\n"
                    "6: Delete a member\n"
                    "7: Edit information from a employee (advisor)\n"
                    "8: Delete an employee (advisor)\n"
                    "9: Update password from an employee (advisor)\n"
                    "10: Update own password\n"
                    "11: List users with rights\n"
                    "12: Search member\n"
                    "13: Log out\n"
                    "14: Exit")
                option = input("Choose option with 1 and 14. Just type the number and hit enter: ")
                if option == "1":
                    res = self.addmember()
                    if res["attack"]:
                        self.logger.log(self.user.username, res["log"], res["add_info"], "Yes")
                        self.forceexit()
                        break
                elif option == "2":
                    res = self.addemployee("advisor")
                    if res["attack"]:
                        self.logger.log(self.user.username, res["log"], res["add_info"], "Yes")
                        self.forceexit()
                        break
                elif option == "3":
                    self.logger.getlogs()
                elif option == "4":
                    self.createbackup()
                elif option == "5":
                    getmembers = self.cursor.execute("SELECT membership_id, full_name FROM members")
                    listmembers = getmembers.fetchall()
                    for x in listmembers:
                        print("ID:", x[0], "Name:", x[1])
                    choosemember = input("Type the membership id of the user who's information needs to be changed: ")
                    try:
                        int(choosemember)
                    except ValueError:
                        self.logger.log(self.user.username, "Change information member",
                                        f" search for member: {choosemember}", "Yes")
                        print("\nThat's not an id, please try again")
                        continue
                    res = self.editmember(choosemember)
                    if res["attack"]:
                        self.logger.log(self.user.username, res["log"], res["add_info"], "Yes")
                        self.forceexit()
                        break
                elif option == "6":
                    getmembers = self.cursor.execute("SELECT membership_id, full_name FROM members")
                    listmembers = getmembers.fetchall()
                    for x in listmembers:
                        print("ID:", x[0], "Name:", x[1])
                    choosemember = input("Type the membership id of the member who needs to be deleted: ")
                    try:
                        int(choosemember)
                    except ValueError:
                        self.logger.log(self.user.username, "Delete member",
                                        f" search for deletion member: {choosemember}", "Yes")
                        print("\nThat's not an id, please try again")
                        continue
                    res = self.deletemember(choosemember)
                    if res["attack"]:
                        self.logger.log(self.user.username, res["log"], res["add_info"], "Yes")
                        self.forceexit()
                        break
                elif option == "7":
                    getemployees = self.cursor.execute("SELECT id, username, first_name, last_name, rights FROM employees "
                                                       "WHERE rights = 'advisor'")
                    listemployees = getemployees.fetchall()
                    for x in listemployees:
                        print("ID:", x[0], "Username:", self.validator.unhash(x[1]),
                              f"Name: {x[2]} {x[3]}", "Right:", x[4])
                    chooseemployee = input("Type the id of the employee (advisor) who's information needs to be changed: ")
                    try:
                        int(chooseemployee)
                    except ValueError:
                        self.logger.log(self.user.username, "Edit employee",
                                        f" search for editing employee: {chooseemployee}", "Yes")
                        print("\nThat's not an id, please try again")
                        continue
                    res = self.editemployee(chooseemployee)
                    if res["attack"]:
                        self.logger.log(self.user.username, res["log"], res["add_info"], "Yes")
                        self.forceexit()
                        break
                elif option == "8":
                    getemployees = self.cursor.execute("SELECT id, username, first_name, last_name, rights FROM employees "
                                                       "WHERE rights = 'advisor'")
                    listemployees = getemployees.fetchall()
                    print("Employees:")
                    for x in listemployees:
                        print(f"ID: {x[0]}, Username: {self.validator.unhash(x[1])}, Name: {x[2]} {x[3]}, Right: {x[4]}")
                    chooseemployee = input("Type the ID of the employee who's needs to be deleted: ")
                    try:
                        int(chooseemployee)
                    except ValueError:
                        self.logger.log(self.user.username, "Delete employee",
                                        f" search for deleting employee: {chooseemployee}", "Yes")
                        print("\nThat's not an id, please try again")
                        continue
                    res = self.deleteemployee(chooseemployee)
                    if res["attack"]:
                        self.logger.log(self.user.username, res["log"], res["add_info"], "Yes")
                        self.forceexit()
                        break
                elif option == "9":
                    getemployees = self.cursor.execute(
                        "SELECT id, username, first_name, last_name, rights FROM employees "
                        "WHERE rights = 'advisor'")
                    listemployees = getemployees.fetchall()
                    for x in listemployees:
                        print("ID:", x[0], "Username:", self.validator.unhash(x[1]),
                              f"Name: {x[2]} {x[3]}, Right: {x[4]}")
                    chooseemployee = input("Type the id of the employee who's password needs to be updated: ")
                    try:
                        int(chooseemployee)
                    except ValueError:
                        self.logger.log(self.user.username, "Change password",
                                        f" search for employee changes password: {chooseemployee}", "Yes")
                        print("\nThat's not an id, please try again")
                        continue
                    res = self.updatepassword(chooseemployee)
                    if res["attack"]:
                        self.logger.log(self.user.username, res["log"], res["add_info"], "Yes")
                        self.forceexit()
                        break
                elif option == "10":
                    self.update_own_password()
                elif option == "11":
                    self.listemployeeswithrights()
                elif option == "12":
                    self.searchmember()
                elif option == "13":
                    self.logout()
                    user_in_menu = False
                elif option == "14":
                    self.exit()
                    break
                else:
                    print("Option does not exists. Please choose again with 1, 2, 3 or 4")
                    continue

            elif self.user.rights == "3": #advisor
                print("\n--OPTIONS--\n"
                      "1: Add a new member\n"
                      "2: Edit information from a member\n"
                      "3: Update own password\n"
                      "4: Search member\n"
                      "5: Log out\n"
                      "6: Exit")
                option = input("Choose option with 1 and 6. Just type the number and hit enter: ")
                if option == "1":
                    res = self.addmember()
                    if res["attack"]:
                        self.logger.log(self.user.username, res["log"], res["add_info"], "Yes")
                        self.forceexit()
                        break
                elif option == "2":
                    getmembers = self.cursor.execute("SELECT id, full_name FROM members")
                    listmembers = getmembers.fetchall()
                    for x in listmembers:
                        print(f"ID: {x[0]}, Name: {x[1]}")
                    choosemember = input("Type the id of the user who's password needs to be changed: ")
                    try:
                        int(choosemember)
                    except ValueError:
                        print("\nThat's not an id, please try again")
                        continue
                    res = self.editmember(choosemember)
                    if res["attack"]:
                        self.logger.log(self.user.username, res["log"], res["add_info"], "Yes")
                        self.forceexit()
                        break
                elif option == "3":
                    self.update_own_password()
                elif option == "4":
                    self.searchmember()
                elif option == "5":
                    self.logout()
                    user_in_menu = False
                elif option == "6":
                    self.exit()
                    break
                else:
                    print("Option does not exists. Please choose again with 1 or 2")
                    continue

    def createbackup(self):  # Creates backup of db by putting it into a new instance + zips both the log file and the backup.db together
        global backup_con
        try:
            backup_con = sqlite3.connect('Sqlite_backup.db')
            with backup_con:
                self.connection.backup(backup_con, pages=0, progress=None)
                self.logger.log(self.user.username, "Backup created from system log and database", "None", "No")
                print("Backup successful created")
        except sqlite3.Error as error:
            print("Error while taking backup: ", error)
        finally:
            if backup_con:
                backup_con.close()

        zipObj = ZipFile(f'Backup {datetime.datetime.now()}.zip', 'w')

        zipObj.write('system_log.csv')
        zipObj.write('Sqlite_backup.db')

        zipObj.close()

    def deletemember(self, membership_id):
        print(f"Deleting member {membership_id}")
        res_delete_member_check = self.validator.checkattack(membership_id)
        if not res_delete_member_check["correct"]:
            print(res_delete_member_check["message"])
            return {"attack": True, "log": ("Malicious input detected at function 'deletemember"),
                    "add_info": f"while deleting member: {membership_id}"}
        self.cursor.execute(f'''DELETE FROM members WHERE membership_id = {membership_id}''')
        self.connection.commit()
        self.logger.log(self.user.username, "Deleted from database", f"member {membership_id} deleted", "No")
        print(f"Succesfully deleted member: {membership_id}")
        return {"attack": False}

    def deleteemployee(self, employee_id):
        print(f"Deleting member {employee_id}")
        res_delete_employee_check = self.validator.checkattack(employee_id)
        if not res_delete_employee_check["correct"]:
            print(res_delete_employee_check["message"])
            return {"attack": True, "log": ("Malicious input detected at function 'deleteemployee"),
                    "add_info": f"while deleting employee: {employee_id}"}
        self.cursor.execute(f'''DELETE FROM employees WHERE id = {employee_id}''')
        self.connection.commit()
        self.logger.log(self.user.username, "Deleted from database", f"employee {employee_id} deleted", "No")
        print(f"Succesfully deleted employee: {employee_id}")
        return {"attack": False}

    def update_own_password(self):
        while True:
            input_password = input("New password: ")
            res_input_password = self.validator.checkattack(input_password)
            if not res_input_password["correct"]:
                print(res_input_password["message"])
                return {"attack": True, "log": res_input_password["message"],
                        "add_info": f"while editing own employee's new password: {input_password}"}
            response = self.validator.checkpassword(input_password)  # Check for password
            if not response["correct"]:
                print(response["message"])
                continue
            break

        hashed_password = self.validator.hash(input_password)  # before adding to the database
        self.cursor.execute('''UPDATE employees SET password = ?  WHERE id = ?''',
                            (hashed_password, self.user.id))
        self.connection.commit()
        print("--Own password updated successfully--")
        self.logger.log(self.user.username, "Updated own password", f" updated password user id: {self.user.id}", "No")
        return {"attack": False}

    def updatepassword(self, employee_id):
        while True:
            input_password = input("New password: ")
            res_input_password = self.validator.checkattack(input_password)
            if not res_input_password["correct"]:
                print(res_input_password["message"])
                return {"attack": True, "log": res_input_password["message"],
                        "add_info": f"while editing employee's new password: {input_password}"}
            response = self.validator.checkpassword(input_password)  # Check for password
            if not response["correct"]:
                print(response["message"])
                continue
            break

        hashed_password = self.validator.hash(input_password)  # before adding to the database
        self.cursor.execute('''UPDATE employees SET password = ?  WHERE id = ?''',
                            (hashed_password, employee_id))
        self.connection.commit()
        print("--Password updated successfully--")
        self.logger.log(self.user.username, "Updated password", f" updated password id: {employee_id}", "No")
        return {"attack": False}

    def listemployeeswithrights(self):
        list_employees = self.cursor.execute("SELECT id, username, rights FROM employees")
        hashed_employees = list_employees.fetchall()
        for x in hashed_employees:
            print("ID:", x[0], "Username:", self.validator.unhash(x[1]), "Right: ", x[2])
        self.logger.log(self.user.username, "List employees with rights",
                        f" all employees with rights", "No")

    def searchmember(self):
        member_to_search = input("Of which member would you like the information? Note : Partial input is also permitted : ")
        search = self.cursor.execute('''SELECT * FROM members WHERE full_name LIKE ?
                                                                     OR membership_id LIKE ? 
                                                                     OR street_and_number LIKE ?
                                                                     OR zipcode LIKE ?
                                                                     OR city LIKE ?
                                                                     OR email LIKE ?
                                                                     OR phone LIKE ?
                                                                     ''', ('%' + member_to_search + '%',
                                                                           '%' + member_to_search + '%',
                                                                           '%' + member_to_search + '%',
                                                                           '%' + member_to_search + '%',
                                                                           '%' + member_to_search + '%',
                                                                           '%' + member_to_search + '%',
                                                                           '%' + member_to_search + '%',))
        self.connection.commit()

        members = search.fetchall()
        for x in members:
            print(f"ID: {x[0]}, Membership ID: {x[1]}, Name: {x[2]}, Street and number: {x[3]}, "
                  f"Zipcode: {x[4]}, City: {x[5]}, Email: {x[6]}, Registration date: {x[7]}")
        self.logger.log(self.user.username, "Searched members", f" input search command: {member_to_search}", "No")

if __name__ == "__main__":
    program = FurnicorFamilySystem()

    program.startsystem()

    program.startloop()
