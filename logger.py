import csv
from time import localtime, strftime
from cryptography.fernet import Fernet

class Logger:

    def __init__(self):
        self.csvFile = "system_log.csv"

    def log(self, user, log, add_info, suspicious):

        file = open('filekey.key', 'r')
        key = file.read()
        
        fernet = Fernet(key)
        

        fields = [strftime("%Y-%m-%d %H:%M:%S", localtime()), user, log, add_info, suspicious]
        enc_fields = []
        with open(self.csvFile, 'a', newline='') as system_log:
            for item in fields:
                enc_field = fernet.encrypt(item.encode())
                enc_fields.append(enc_field)
            writer = csv.writer(system_log)
            writer.writerow(enc_fields)

    def getlogs(self):
        
        file = open('filekey.key', 'r')
        key = file.read()

        fernet = Fernet(key)


        with open(self.csvFile) as system_log:
            reader = csv.reader(system_log, delimiter=",")
            line_count = 0

            for row in reader:
                dec_fields = []
                for item in row:
                    dec_field = fernet.decrypt(bytes(item[1:], 'utf-8')).decode()
                    dec_fields.append(dec_field)
                if line_count == 0:
                    print(f"No      timestamp      username     desciption           addition info       suspicious")
                    print(f"{line_count}  {dec_fields[0]}    {dec_fields[1]}       {dec_fields[2]}           {dec_fields[3]}            {dec_fields[4]}")
                    line_count += 1
                else:
                    print(f"{line_count}  {dec_fields[0]}    {dec_fields[1]}       {dec_fields[2]}           {dec_fields[3]}            {dec_fields[4]}")
                    line_count += 1
