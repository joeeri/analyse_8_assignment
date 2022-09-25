import sqlite3


class Validator:

    def __init__(self):
        self.uppercase_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"  # last : 25
        self.lowercase_letters = "abcdefghijklmnopqrstuvwxyz"
        self.numbers = "0123456789"
        self.specials = "~!@#$%^&*_-+=`|\(){}[]:;'<>,.?/"
        self.specials_email = ["!", "#", "$", "%", "&", "'", "*", "+", "-", "/", "=", "?", "^", "_", "`", "{", "|", "}",
                             "~", "."]
        self.cities = {"1": "Rotterdam", "2": "Den Haag", "3": "Amsterdam", "4": "Leiden", "5": "Utrecht",
                          "6": "Arnhem", "7": "Nijmegen", "8": "Enschede", "9": "Groningen", "10": "Leeuwaarden"}
        self.rights = {"1": "systemadmin", "2": "advisor"}
        self.red_flags_sql_injection = ["alter", "begin", "break", "commit", "create", "cursor", "drop", "insert", "update",
                            "while", ";", "--"]
        self.hash_number = 2

    def checkusername(self, input_username):
        usernameCharacters = self.lowercase_letters + self.numbers + ".-_'"
        if len(input_username) < 6 or len(input_username) > 10:  # Checks the length
            return {"correct": False, "message": "Username must be between 6 and 10 characters, please try again"}
        # elif input_username[0] not in self.lowercase_letters:  # Checks if the first character is a letter
        elif not input_username[0].isalpha():
            return {"correct": False, "message": "Username must start with a letter, please try again"}
        elif all(c in usernameCharacters for c in input_username):
            return {"correct": True, "message": None}
        else:
            return {"correct": False,
            "message": "Username is incorrect. It can only contain [letters, numbers, '-', '_', '\'', '.'], please try again"}
        # for sym in input_username:  # Check all characters
        #     if sym not in self.lowercase_letters and sym not in self.numbers and sym != '-' and sym != '_' and sym != '\'' and sym != '.':
        #         return {"correct": False,
        #                 "message": "Username is incorrect. It can only contain [letters, numbers, '-', '_', '\'', '.'], please try again"}

    def checkpassword(self, input_password):
        if len(input_password) < 8 or len(input_password) > 30:  # Check length
            return {"correct": False, "message": "Password must be between 8 and 30 characters"}
        for sym in input_password:  # Check all symbols
            if sym not in self.lowercase_letters and sym not in self.uppercase_letters and sym not in self.numbers and sym not in self.specials:
                return {"correct": False, "message": "Password contains wrong characters"}
        lowercase = 0
        uppercase = 0
        digit = 0
        special = 0
        for sym in input_password:
            if sym in self.lowercase_letters:
                lowercase += 1
            elif sym in self.uppercase_letters:
                uppercase += 1
            elif sym in self.numbers:
                digit += 1
            elif sym in self.specials:
                special += 1
        if lowercase == 0 or uppercase == 0 or digit == 0 or special == 0:
            return {"correct": False, "message": "Password combination is not sufficient"}
        return {"correct": True, "message": None}

    def checkzipcode(self, zipcode):
        zipcode = zipcode.upper()
        if len(zipcode) != 6:
            return {"correct": False, "message": "Zipcode is not the right, please try again"}
        for char in zipcode[:4]:
            if char not in self.numbers:
                return {"correct": False, "message": "First four characters are not digits, please try again"}
        for char in zipcode[4:6]:
            if char not in self.uppercase_letters:
                return {"correct": False, "message": "Zipcode is not the right, please try again"}
        return {"correct": True, "message": None}

    def checkphonenumber(self, phonenumber):
        if len(phonenumber) != 15 or phonenumber[:6] != "+31-6-":
            return {"correct": False, "message": "Phone number is incorrect, please try again"}
        digit = 6
        while digit <= 14:
            if digit == 10 and phonenumber[digit] != "-":
                return {"correct": False, "message": "Phone number is incorrect, please try again"}
            if digit != 10 and phonenumber[digit] not in self.numbers:
                return {"correct": False, "message": "Phone number is incorrect, please try again"}
            digit += 1
        return {"correct": True, "message": None}

    def checkemail(self, email):
        if len(email) > 128:
            return {"correct": False, "message": "Email is longer than 128 characters, please try again"}
        if email.count("@") != 1:
            return {"correct": False, "message": "Email must be like: (yourname@domain.com), please try again"}

        email_splitted = email.split("@")
        local_part = email_splitted[0]
        index = 0
        dots = 0
        while index < len(local_part):
            char = local_part[index]
            if char in self.uppercase_letters or char in self.lowercase_letters or char in self.specials_email:
                if char == ".":
                    dots += 1
                else:
                    dots = 0
                if dots == 2:
                    return {"correct": False, "message": "Email can't have a dot after dot"}
                else:
                    index += 1
            else:
                return {"correct": False, "message": "Email must be like: (yourname@domain.com), please try again"}

        domain = email_splitted[1]  # Checking the second part (domain) of email

        if domain.count(".") != 1:
            return {"correct": False, "message": "Email must be like: (yourname@domain.com), please try again"}

        domain_splitted = domain.split(".")
        host = domain_splitted[0]  # Checking if host is correct format
        if host[0] == "-" or host[-1] == "-":
            return {"correct": False, "message": "Email must be like: (yourname@domain.com), please try again"}
        for char in host:
            if char in self.uppercase_letters or char in self.lowercase_letters or char in self.numbers or char == "-":
                continue
            else:
                return {"correct": False, "message": "Email must be like: (yourname@domain.com), please try again"}

        label = domain_splitted[1]
        if len(label) != 2 and len(label) != 3:
            return {"correct": False, "message": "Email must be like: (yourname@domain.com), please try again"}
        for char in label:
            if char not in self.uppercase_letters and char not in self.lowercase_letters:
                return {"correct": False, "message": "Email must be like: (yourname@domain.com), please try again"}
        return {"correct": True}

    def validateserver(self, user_input):  # If server generated input that is not correct format, the session stops
        white_list = self.numbers
        if user_input not in white_list:
            return {"correct": False, "message": "- The system detected suspicious activity and ended this session -"}
        return {"correct": True, "message": None}

    def checkattack(self, input_string):
        for redFlag in self.red_flags_sql_injection:
            if redFlag in input_string:
                return {"correct": False, "message": "Session closed because the input contains SQL-like language"}
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

