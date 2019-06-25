# YARSA [![Python 3.7](https://img.shields.io/badge/python-3.7-blue.svg)](https://www.python.org/downloads/release/python-370/)

Yet Another RSA Toolkit

## Why do you need another one

* Many of the Existing ones are too slow
* They have additional unnecessary things
* They are unnecessarily complicated

## Features

* Simple RSA Decryption
* Factorization of n if p and q not given (Using factordb and alpertron)
* Small e Attack
* Weiner's Small d Attach
* Multi-Prime RSA
* Chinese Remainder Attack

## Installation

* Clone the Repository

`git clone --recurse-submodules https://github.com/jatinluthra14/YARSA && cd YARSA`

* Install gmpy2
YARSA requires gmpy2 which needs to be installed on your OS
For Linux:
`sudo apt-get install libgmp3-dev`

* Install rest requiremnts
`pip install -r requirements`

## Extra Libraries

* [Wiener Attack](https://github.com/pablocelayes/rsa-wiener-attack)

## TODO

* Implement the features
* Add alpertron factorization support
