import sqlite3
import re as regex


class Validator:

    def __init__(self):
        self.uppercase_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"  # last : 25
        self.lowercase_letters = "abcdefghijklmnopqrstuvwxyz"
        self.numbers = "0123456789"
        self.specials = "~!@#$%^&*_-+=`|\(){}[]:;'<>,.?/"
        self.specials_email = ["!", "#", "$", "%", "&", "'", "*", "+", "-", "/", "=", "?", "^", "_", "`", "{", "|", "}",
                             "~", "."]
        self.zipcode = regex.compile("^[0-9]{4}[A-Za-z]{2}$")
        self.email = regex.compile("^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$")
        self.mobile = regex.compile("^\+[0-9]{8}$")
        self.cities = {"1": "Rotterdam", "2": "Den Haag", "3": "Amsterdam", "4": "Leiden", "5": "Utrecht",
                          "6": "Arnhem", "7": "Nijmegen", "8": "Enschede", "9": "Groningen", "10": "Leeuwaarden"}
        self.rights = {"systemadmin" : "2", "advisor": "3"}
        self.red_flags_sql_injection = ["alter", "begin", "break", "commit", "create", "cursor", "drop", "select" ,"insert", "update",
                            "while", ";", "--"]
        self.hash_number = 2

    def checkusername(self, input_username):
        usernameCharacters = self.lowercase_letters + self.numbers + "_'."
        if all(c in usernameCharacters for c in input_username) and input_username[0].isalpha() \
                and len(input_username) > 5 and len(input_username) < 11:
            return {"correct": True, "message": None}
        else:
            return {"correct": False,
            "message": "Username is incorrect. It can only start with a letter and must be between 6 and 10 characters.\n"
                       "It can only contain [letters, numbers and (_), ('), (.)], please try again\n"}

    def checkpassword(self, input_password):
        passwordCharacters = self.lowercase_letters + self.uppercase_letters + self.numbers + self.specials
        if all(c in passwordCharacters for c in input_password) and any(c in self.lowercase_letters for c in input_password) \
            and any(c in self.uppercase_letters for c in input_password) and any(c in self.numbers for c in input_password) \
            and any(c in self.specials for c in input_password) and len(input_password) > 7 and len(input_password) < 31:
            return {"correct": True, "message": None}
        else:
            return {"correct": False,
                    "message": "Password is incorrect. It must be between 8 and 30 characters.\n"
                               "It must contain at least one: lowercase letter, uppercase letter, number and "
                               "special character: ~!@#$%^&*_-+=`|\(){}[]:;'<>,.?/, please try again\n"}

    def checkname(self, name):
        nameCharacters = self.lowercase_letters + self.uppercase_letters
        if all(c in nameCharacters for c in name) and (name is not None) and len(name) > 0 and len(name) < 51:
            return {"correct": True, "message": None}
        else:
            return {"correct": False,
                    "message": "Field is required and name can only contain letters and cannot be longer than 50 characters"}

    def checkstreet(self, street):
        streetCharacters = self.lowercase_letters + self.uppercase_letters
        if all(c in streetCharacters for c in street) and (street is not None) and len(street) > 0 and len(street) < 51:
            return {"correct": True, "message": None}
        else:
            return {"correct": False,
                    "message": "Field is required and street can only contain letters and cannot be longer than 50 characters"}

    def checkhousenumber(self, housenumber):
        housenumberCharacters = self.numbers + self.lowercase_letters + self.uppercase_letters
        if all(c in housenumberCharacters for c in housenumber) and (housenumber is not None) and len(housenumber) > 0 and len(housenumber) < 7:
            return {"correct": True, "message": None}
        else:
            return {"correct": False,
                    "message": "Field is required and housenumber cannot be longer than 6 characters"}

    def checkzipcode(self, input_zipcode):
        if (input_zipcode is not None) and self.zipcode.search(input_zipcode) and len(input_zipcode) < 7:
            return {"correct": True, "message": None}
        else:
            return {"correct": False, "message": f"Zipcode [{input_zipcode}] is not right, please try again"}

    def checkphonenumber(self, phonenumber):
        if all(c in self.numbers for c in phonenumber) and len(phonenumber) > 0 and len(phonenumber) < 9:
            return {"correct": True, "message": None}
        else:
            return {"correct": False, "message": f"Phonenumber +31-6-[{phonenumber}] is not right, please try again"}

    def checkemail(self, email):
        if (email is not None) and self.email.search(email) and len(email) < 129:
            return {"correct": True, "message": None}
        else:
            return {"correct": False, "message": f"Email must be like: (yourname@domain.com), please try again"}

    def validateserver(self, user_input):  # If server generated input that is not correct format, the session stops
        white_list = self.numbers
        if user_input not in white_list:
            return {"correct": False, "message": "- The system detected suspicious activity and ended this session -"}
        return {"correct": True, "message": None}

    def validateright(self, user_input):  # If server generated input that is not correct format, the session stops
        white_list = self.rights
        if user_input not in white_list:
            return {"correct": False, "message": "- The system detected suspicious activity and ended this session -"}
        return {"correct": True, "message": None}


    def validatelist(self, member_list, user_input):  # Checks if the input generated by the user is in the database
        if user_input in member_list:
                return {"correct": True, "message": None}
        else:
            return {"correct": False, "message": "\nMembership ID not found, please try again"}

    def checkattack(self, input_string):
        for redFlag in self.red_flags_sql_injection:
            if redFlag in input_string:
                return {"correct": False, "message": "\nSession closed because the input contains SQL-like language"}
        return {"correct": True, "message": None}

    def hash(self, input_string):  # Moves every character in the string an x amount (Defined as field of this class) of indexes forward
        hashed_string = ""
        for char in input_string:
            if char in self.uppercase_letters:
                char_index = self.uppercase_letters.index(char)
                if char_index + self.hash_number < len(self.uppercase_letters):
                    hashed_string += self.uppercase_letters[char_index + self.hash_number]
                else:
                    new_index = char_index + self.hash_number - len(self.uppercase_letters)
                    hashed_string += self.uppercase_letters[new_index]
            if char in self.lowercase_letters:
                char_index = self.lowercase_letters.index(char)
                if char_index + self.hash_number < len(self.lowercase_letters):
                    hashed_string += self.lowercase_letters[char_index + self.hash_number]
                else:
                    new_index = char_index + self.hash_number - len(self.lowercase_letters)
                    hashed_string += self.lowercase_letters[new_index]
            if char in self.numbers:
                char_index = self.numbers.index(char)
                if char_index + self.hash_number < len(self.numbers):
                    hashed_string += self.numbers[char_index + self.hash_number]
                else:
                    new_index = char_index + self.hash_number - len(self.numbers)
                    hashed_string += self.numbers[new_index]
            if char in self.specials:
                char_index = self.specials.index(char)
                if char_index + self.hash_number < len(self.specials):
                    hashed_string += self.specials[char_index + self.hash_number]
                else:
                    new_index = char_index + self.hash_number - len(self.specials)
                    hashed_string += self.specials[new_index]

        return hashed_string

    def unhash(self, input_string):
        unhashed_string = ""

        for char in input_string:
            if char in self.uppercase_letters:
                char_index = self.uppercase_letters.index(char)
                if char_index - self.hash_number >= 0:
                    unhashed_string += self.uppercase_letters[char_index - self.hash_number]
                else:
                    new_index = len(self.uppercase_letters) - (self.hash_number - char_index)  # Wraparound needed
                    unhashed_string += self.uppercase_letters[new_index]
            if char in self.lowercase_letters:
                char_index = self.lowercase_letters.index(char)
                if char_index - self.hash_number >= 0:
                    unhashed_string += self.lowercase_letters[char_index - self.hash_number]
                else:
                    new_index = len(self.lowercase_letters) - (self.hash_number - char_index)  # Wraparound needed
                    unhashed_string += self.lowercase_letters[new_index]
            if char in self.numbers:
                char_index = self.numbers.index(char)
                if char_index - self.hash_number >= 0:
                    unhashed_string += self.numbers[char_index - self.hash_number]
                else:
                    new_index = len(self.numbers) - (self.hash_number - char_index)  # Wraparound needed
                    unhashed_string += self.numbers[new_index]
            if char in self.specials:
                char_index = self.specials.index(char)
                if char_index - self.hash_number >= 0:
                    unhashed_string += self.specials[char_index - self.hash_number]
                else:
                    new_index = len(self.specials) - (self.hash_number - char_index)  # Wraparound needed
                    unhashed_string += self.specials[new_index]

        return unhashed_string

