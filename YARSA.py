import os
import sys
import requests
import re
from Crypto.Util.number import long_to_bytes
import argparse

class YARSA:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Yet Another RSA Toolkit")
    parser.add_argument('--params-file', help='file which store params like n, e, c and/or others')
    args = parser.parse_args()
    
    if len(sys.argv) < 2:
        print('Please choose an option!')
        exit(0)
    
    params = extract_params(args.params_file)
    print(params)