import getopt
import sys
from passlib.hash import sha512_crypt
from threading import Thread


USERNAME_INDEX = 0
PASSWORD_INDEX = 1
SALT_INDEX = 2


def main(argv):
    password_file, dictionary_file = get_opts_from(argv)
    print('[*] Attempting to crack users in "' + str(password_file) + '" using ' + str(dictionary_file))
    with open(password_file) as passwords:
        for line in passwords:
            values = line.split(':')
            t = Thread(target=crack_password, args=(values[USERNAME_INDEX], values[PASSWORD_INDEX], dictionary_file))
            t.start()


def get_opts_from(argv):
    if len(argv) < 4:
        print_usage_and_exit()

    password_file, dictionary_file = '', ''
    opts, args = getopt.getopt(argv, 'f:d:', ['--file=', '--dictionary='])
    for opt, arg in opts:
        if opt in ('-f', '--file'):
            password_file = arg
        elif opt in ('-d', '--dictionary'):
            dictionary_file = arg
        else:
            print_usage_and_exit()

    return password_file, dictionary_file


def print_usage_and_exit():
    print('Usage: pw-cracker.py -f <password_file> -d <dictionary_file>')
    exit(1)


def crack_password(username, password, dictionary_file):
    salt = password.split('$')
    if len(salt) > SALT_INDEX:
        salt = salt[SALT_INDEX]
        with open(dictionary_file) as dictionary_file:
            for candidate in dictionary_file:
                candidate = candidate.rstrip('\n')
                candidate_hash = sha512_crypt.using(rounds=5000).using(salt=salt).hash(candidate.encode('utf-8'))
                if candidate_hash == password:
                    print('[+] Found password: [' + candidate + '] for: ' + username)
                    found = True
                    return
    print('[-] No password found for: ' + username)


if __name__ == '__main__':
    main(sys.argv[1:])
