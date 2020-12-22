import json
import sys
import argparse
import threading

from common.common import *
from common.logger import Log
from common.corscheck import CORSCheck

import gevent
from gevent import monkey
monkey.patch_all()
from gevent.pool import Pool
from gevent.queue import Queue
from colorama import init

# Globals
results = []

def banner():
    print(("""%s
   ____ ___  ____  ____   ____    _    _   _ _   _ _____ ____  
  / ___/ _ \|  _ \/ ___| / ___|  / \  | \ | | \ | | ____|  _ \ 
 | |  | | | | |_) \___ \| |     / _ \ |  \| |  \| |  _| | |_) |
 | |__| |_| |  _ < ___) | |___ / ___ \| |\  | |\  | |___|  _ < 
  \____\___/|_| \_\____/ \____/_/   \_\_| \_|_| \_|_____|_| \_\
                                                               %s%s
        # Coded By Jianjun Chen - whucjj@gmail.com%s
    """ % ('\033[91m', '\033[0m', '\033[93m', '\033[0m')))


def parser_error(errmsg):
    banner()
    print(("Usage: python " + sys.argv[0] + " [Options] use -h for help"))
    print(("Error: " + errmsg))
    sys.exit()


def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(
        epilog='\tExample: \r\npython ' + sys.argv[0] + " -u google.com")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument(
        '-u', '--url', help="URL/domain to check it's CORS policy")
    parser.add_argument(
        '-i',
        '--input',
        help='URL/domain list file to check their CORS policy')
    parser.add_argument(
        '-t',
        '--threads',
        help='Number of threads to use for CORS scan',
        type=int,
        default=50)
    parser.add_argument('-o', '--output', help='Save the results to json file')
    parser.add_argument(
        '-v',
        '--verbose',
        help='Enable Verbosity and display results in realtime',
        nargs='?',
        default=False)
    parser.add_argument('-d', '--headers', help='Add headers to the request.', default=None, nargs='*')
    args = parser.parse_args()
    if not (args.url or args.input):
        parser.error("No url inputed, please add -u or -i option")
    return args


# Synchronize results
c = threading.Condition()

def scan(cfg, log):
    global results

    while not cfg["queue"].empty():
        try:
            item = cfg["queue"].get(timeout=1.0)
            cors_check = CORSCheck(item, cfg)
            msg = cors_check.check_one_by_one()

            # Keeping results to be written to file only if needed
            if log.filename and msg:
                c.acquire()
                results.append(msg)
                c.release()
        except Exception as e:
            print(e)
            break

def cors_check(url, headers=None):
    # 0: 'DEBUG', 1: 'INFO', 2: 'WARNING', 3: 'ALERT', 4: 'disable log'
    log = Log(None, print_level=4)
    cfg = {"logger": log, "headers": headers}

    cors_check = CORSCheck(url, cfg)
    #msg = cors_check.check_all_in_parallel()
    msg = cors_check.check_one_by_one()
    return msg

def main():
    init()
    args = parse_args()
    banner()

    queue = Queue()
    log_level = 1 if args.verbose else 2  # 1: INFO, 2: WARNING

    log = Log(args.output, log_level)
    cfg = {"logger": log, "queue": queue, "headers": parse_headers(args.headers)}

    read_urls(args.url, args.input, queue)

    print("Starting CORS scan...")
    threads = [gevent.spawn(scan, cfg, log) for i in range(args.threads)]

    try:
        gevent.joinall(threads)
    except KeyboardInterrupt as e:
        pass

    # Writing results file if output file has been set
    if log.filename:
        with open(log.filename, 'w') as output_file:
            output_file.write(json.dumps(results, indent=4))
            output_file.close()
    print("Finished CORS scanning...")


if __name__ == '__main__':
    main()
