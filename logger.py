import csv
from time import localtime, strftime


class Logger:

    def __init__(self):
        self.csvFile = "system_log.csv"

    def log(self, user, log, add_info, suspicious):
        fields = [strftime("%Y-%m-%d %H:%M:%S", localtime()), user, log, add_info, suspicious]
        with open(self.csvFile, 'a', newline='') as system_log:
            writer = csv.writer(system_log)
            writer.writerow(fields)

    def getlogs(self):
        print()
        with open(self.csvFile) as system_log:
            reader = csv.reader(system_log, delimiter=",")
            line_count = 0
            for row in reader:
                if line_count == 0:
                    print(f"No      timestamp      username     desciption           addition info       suspicious")
                    print(f"{line_count}  {row[0]}    {row[1]}       {row[2]}           {row[3]}            {row[4]}")
                    line_count += 1
                else:
                    print(f"{line_count}  {row[0]}    {row[1]}       {row[2]}           {row[3]}            {row[4]}")
                    line_count += 1
