import os
import sys
import requests
import re
from Crypto.Util.number import long_to_bytes, inverse
import argparse
import gmpy2
import primefac
from contextlib import contextmanager
import pyperclip
from math import ceil, sqrt


@contextmanager
def suppress_stdout():
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:
            yield
        finally:
            sys.stdout = old_stdout


def extract_params(**kwargs):
    params = dict()
    if 'params_file' in kwargs:
        with open(kwargs['params_file'], "r") as fp:
            file_contents = fp.read()
    elif 'clipboard' in kwargs:
        file_contents = pyperclip.paste()
        if not kwargs['silent']:
            print("Copied Clipboard Contents:\n"+file_contents)
    else:
        if not kwargs['silent']:
            print("No Params specified!")
        exit(0)

    n = re.search('[n|N]\s*[:=()]+\s*(.*)', file_contents)
    p = re.search('[p|P]\s*[:=()]+\s*(.*)', file_contents)
    q = re.search('[q|Q]\s*[:=()]+\s*(.*)', file_contents)
    m = re.search('[m|M]\s*[:=()]+\s*(.*)', file_contents)
    e = re.search('[e|E]\s*[:=()]+\s*(.*)', file_contents)
    c = re.search('[c|C]\s*[:=()]+\s*(.*)', file_contents)
    if n:
        if n.group(1).startswith('0x'):
            params['n'] = int(n.group(1), 16)
        else:
            params['n'] = int(n.group(1))
    if p:
        if p.group(1).startswith('0x'):
            params['p'] = int(p.group(1), 16)
        else:
            params['p'] = int(p.group(1))
    if q:
        if q.group(1).startswith('0x'):
            params['q'] = int(q.group(1), 16)
        else:
            params['q'] = int(q.group(1))
    if m:
        if m.group(1).startswith('0x'):
            params['m'] = int(m.group(1), 16)
        else:
            params['m'] = int(m.group(1))
    if e:
        if e.group(1).startswith('0x'):
            params['e'] = int(e.group(1), 16)
        else:
            params['e'] = int(e.group(1))
    if c:
        if c.group(1).startswith('0x'):
            params['c'] = int(c.group(1), 16)
        else:
            params['c'] = int(c.group(1))
    return params


class YARSA:
    def __init__(self, args, **kwargs):
        self.n = None
        self.e = None
        self.c = None
        self.d = None
        self.phi = None
        self.m = None
        self.args = args
        self.__dict__.update(kwargs)
        self.session = requests.session()
        gmpy2.get_context().precision = 50000

    def factorize(self):
        self.print_not_silent("Finding Primes on factordb")
        if self.factordb():
            return True
        else:
            self.print_not_silent("Trying Last Resort! (If it hangs, quit!!)")
            if self.find_primes():
                return True
            else:
                return False

    def find_primes(self):
        try:
            list_primes = list(primefac.primefac(self.n))
            if self.args.list_primes:
                self.print_not_silent("Found Prime Factors:")
                self.print_not_silent(list_primes)
            self.phi = 1
            for prime in list_primes:
                self.phi *= int(prime) - 1
            return True
        except:
            return False

    def factordb(self):
        base_url = "http://factordb.com/api"
        results = self.session.get(
            base_url, params={"query": str(self.n)}).json()
        if results['status'] != 'CF' and results['status'] != 'FF':
            return False
        else:
            if self.args.list_primes:
                self.print_not_silent("Found Factors:")
                self.print_not_silent(results['factors'])
            self.phi = 1
            for factor in results['factors']:
                self.phi *= (int(factor[0]) - 1) ** factor[1]
            return True

    def final_dec(self):
        if not self.d:
            self.d = inverse(self.e, self.phi)
        self.m = pow(self.c, self.d, self.n)
        if self.m:
            return True
        else:
            self.print_not_silent("Couldn't Decrypt")
            return False

    def formatted(self, s):
        return f"-----------------------------------------------------------\nDEC: {self.m}\nHEX: {hex(self.m)}\nASCII: {long_to_bytes(self.m).decode('utf-8', errors='ignore')}\n-----------------------------------------------------------"

    def search_for_attacks(self):
        if self.small_e():
            self.print_not_silent("Attacking RSA with small e")
            self.print_dec()
            exit(0)
        if self.wiener():
            self.print_not_silent('Hit Wiener Attack!')
            self.print_dec()
            exit(0)
        if self.fermat():
            self.print_not_silent('Hit Fermat Factorization!')
            self.print_dec()
            exit(0)

    def small_e(self):
        if self.e in range(1, 18):
            root = gmpy2.root(self.c, self.e)
            if root > gmpy2.root(self.n, self.e):
                return False
            else:
                self.m = int(root)
                return True
        else:
            return False

    def wiener(self):
        sys.path.insert(0, './modules/wiener')
        from RSAwienerHacker import hack_RSA
        with suppress_stdout():
            d = hack_RSA(self.e, self.n)
        if d:
            self.d = d
            self.final_dec()
            return True
        else:
            return False

    def fermat(self):
        factors = []
        a = int(gmpy2.sqrt(self.n))
        b = a*a - self.n
        count = 0
        while True:
            count += 1
            if count == 1000000:
                break
            a += 1
            b = a*a - self.n
            if gmpy2.is_square(b):
                b = int(gmpy2.sqrt(b))
                factors.append(a+b)
                factors.append(a-b)
                temp_n = 1
                self.phi = 1
                for factor in factors:
                    temp_n *= factor
                    self.phi *= factor - 1
                if temp_n == self.n:
                    if self.args.list_primes:
                        self.print_not_silent("Found Factors:")
                        self.print_not_silent(factors)
                    if self.final_dec():
                        return True
        return False

    def print_not_silent(self, s):
        if not self.args.silent:
            print(s)

    def print_dec(self):
        if self.args.flag_format:
            try:
                self.flag = re.search(
                    f"({self.args.flag_format})", self.formatted(self.m)).group(1)
                self.print_not_silent(
                    f"Found a flag in plaintext:\n------------------")
                print(self.flag)
                self.print_not_silent("------------------")
                if not self.args.silent:
                    opt = input(
                        'Do you still want to see plaintext(s)? (y/N): ')
                    if opt:
                        if opt.lower()[0] == 'y':
                            self.print_not_silent(
                                "Okay, Printing Plaintext(s)")
                            print(self.formatted(self.m))
                            exit(0)
                    self.print_not_silent(
                        "Copying the flag to clipboard!")
                pyperclip.copy(self.flag)
                exit(0)
            except Exception as e:
                pass
        self.print_not_silent("Found Plaintext(s): ")
        print(self.formatted(self.m))


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Yet Another RSA Toolkit")
    parser.add_argument('-pf', '--params-file',
                        help='file which store params like n, e, c and/or others')
    parser.add_argument(
        '-cp', '--clipboard', help='copy params from clipboard automatically', action='store_true')
    parser.add_argument('-na', '--no-attacks',
                        help='skip attacks and try old school RSA decryption', action='store_true')
    parser.add_argument('-lp', '--list-primes',
                        help='list all the prime factors if found', action='store_true')
    parser.add_argument(
        '-s', '--silent', help='just print the plaintext', action='store_true')
    parser.add_argument('-ff', '--flag-format',
                        help='The known flag format(regex) to search for, otherwise displays everything')
    args = parser.parse_args()

    if not args.params_file and not args.clipboard:
        print("Please specify the params!")
        exit(0)
    elif args.params_file:
        params = extract_params(
            params_file=args.params_file, silent=args.silent)
    else:
        params = extract_params(clipboard=True, silent=args.silent)
    yarsa = YARSA(args, **params)
    if not args.no_attacks:
        yarsa.search_for_attacks()
    factors = yarsa.factorize()
    if factors:
        final_dec = yarsa.final_dec()
        if final_dec:
            yarsa.print_dec()
