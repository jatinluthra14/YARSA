import os
import sys
import requests
import re
from Crypto.Util.number import long_to_bytes, inverse
import argparse
import gmpy2
import primefac
from contextlib import contextmanager

@contextmanager
def suppress_stdout():
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:  
            yield
        finally:
            sys.stdout = old_stdout

def extract_params(params_file):
    params = dict()
    with open(params_file,"r") as fp:
        file_contents = fp.read()

    n = re.search('[n|N]\s*[:=()]+\s*(.*)', file_contents)
    p = re.search('[p|P]\s*[:=()]+\s*(.*)', file_contents)
    q = re.search('[q|Q]\s*[:=()]+\s*(.*)', file_contents)
    m = re.search('[m|M]\s*[:=()]+\s*(.*)', file_contents)
    e = re.search('[e|E]\s*[:=()]+\s*(.*)', file_contents)
    c = re.search('[c|C]\s*[:=()]+\s*(.*)', file_contents)    
    if n:
        if n.group(1).startswith('0x'):
            params['n'] = int(n.group(1),16)
        else:
            params['n'] = int(n.group(1))
    if p:
        if p.group(1).startswith('0x'):
            params['p'] = int(p.group(1),16)
        else:
            params['p'] = int(p.group(1))
    if q:
        if q.group(1).startswith('0x'):
            params['q'] = int(q.group(1),16)
        else:
            params['q'] = int(q.group(1))
    if m:
        if m.group(1).startswith('0x'):
            params['m'] = int(m.group(1),16)
        else:
            params['m'] = int(m.group(1))
    if e:
        if e.group(1).startswith('0x'):
            params['e'] = int(e.group(1),16)
        else:
            params['e'] = int(e.group(1))
    if c:
        if c.group(1).startswith('0x'):
            params['c'] = int(c.group(1),16)
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
        self.m =None
        self.args = args
        self.__dict__.update(kwargs)
        self.session = requests.session()
        gmpy2.get_context().precision=50000

    def factorize(self):
        print("Finding Primes on factordb")
        if self.factordb():
            return True
        else:
            print("Trying Last Resort! (If it hangs, quit!!)")
            if self.find_primes():
                return True
            else:
                return False
    
    def find_primes(self):
        try:
            list_primes = list(primefac.primefac(self.n))
            if args.list_primes:
                print("Found Prime Factors:")
                print(list_primes)
            self.phi = 1
            for prime in list_primes:
                self.phi *= int(prime) - 1
            return True
        except:
            return False

            
    def factordb(self):
        base_url = "http://factordb.com/api"
        results = self.session.get(base_url, params={"query": str(self.n)}).json()
        if results['status'] != 'CF' and results['status'] != 'FF':
            return False
        else:
            if args.list_primes:
                print("Found Factors:")
                print(results['factors'])
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
            print("Couldn't Decrypt")
            return False
    
    def print_dec(self):
        print('-----------------------------------------------------------')
        print(f"DEC: {self.m}")
        print(f"HEX: {hex(self.m)}")
        print(f"ASCII: {long_to_bytes(self.m).decode('utf-8', errors='ignore')}")
        print('-----------------------------------------------------------')

    def search_for_attacks(self):
        if self.small_e():
            print("Attacking RSA with small e")
            self.print_dec()
            exit(0)
        if self.wiener():
            print('Hit Wiener Attack!')
            self.print_dec()
            exit(0)
    
    def small_e(self):
        if self.e in range(1,18):
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Yet Another RSA Toolkit")
    parser.add_argument('-pf','--params-file', help='file which store params like n, e, c and/or others')
    parser.add_argument('-na','--no-attacks', help='skip attacks and try old school RSA decryption', action='store_true')
    parser.add_argument('-lp','--list-primes', help='list all the prime factors if found', action='store_true')
    args = parser.parse_args()
    
    if len(sys.argv) < 2:
        print('Please choose an option!')
        exit(0)
    
    params = extract_params(args.params_file)
    yarsa = YARSA(args, **params)
    if not args.no_attacks:
        yarsa.search_for_attacks()
    factors = yarsa.factorize()
    if factors:
        final_dec = yarsa.final_dec()
        if final_dec:
            yarsa.print_dec()