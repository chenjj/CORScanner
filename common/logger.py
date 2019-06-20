import time
import json
import sys


class Log:
    """Class Log for logging CORS misconfiguration message"""
    print_level = 0
    msg_level = {0: 'DEBUG', 1: 'INFO', 2: 'WARNING', 3: 'ALERT'}
    auto_timestamp = 1

    def __init__(self, filename, print_level, auto_timestamp=1):
        self.filename = filename
        self.print_level = print_level
        self.auto_timestamp = auto_timestamp

    def write(self, msg, level=0, auto_timestamp=1):
        try:
            if level >= self.print_level:
                if self.auto_timestamp == 1:
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S",
                                              time.localtime())
                    record = "%s %s %s" % (timestamp, self.msg_level[level],
                                           msg)
                    sys.stdout.write(record + "\r\n")
                else:
                    sys.stdout.write(msg + "\r\n")
                sys.stdout.flush()
        except KeyboardInterrupt:
            self.close()

    def debug(self, msg):
        self.write(msg, 0)

    def info(self, msg):
        self.write(msg, 1)

    def warning(self, msg):
        record = "Found misconfiguration! " + json.dumps(msg)
        self.write("""%s%s%s""" % ('\033[91m', record, '\033[0m'), 2)

    def alert(self, msg):
        self.write(msg, 3)

    def close(self):
        if self.log:
            self.log.close()
