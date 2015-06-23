# IEEE P1735 decryptor
## Preface
[IEEE P1735](http://www.eda.org/twiki/bin/view.cgi/P1735/WebHome) is a draft standard that defines methods of encryption of IP cores. Both VHDL and Verilog files can be encrypted, while syntax is a bit different for those file types. Although still a draft, it is widely supported by various vendors including Xilinx, Mentor Graphics, Aldec, Synopsys and others. Unfortunately, at this time no public documentation on this standard is available.

## Why encryption is a BAD idea
The most frustrating thing aboud encrypting IP cores is that a piece of software (say, modelsim) sooner or later *decrypts* it. Decryption is done at *source level*, i.e. it is possible to recover full source code of encryped module (provided you have an extracted private key from the software you're using). Usually software vendors do not care much about hiding their private keys.
The decryption is done in two stages. First, using the private key, a session key is decrypted using RSA decryption procedure. Second, data block is decoded using this session key and AES-128-CBC decryption procedure. 

## Usage
First, set up ``PYTHONPATH`` to point to ``P1735Parser.py`` location and ``PATH`` -- to ``decrypt.py`` (or simply run ``decrypt.py`` from local directory).

Example usage:
```sh
decrypt.py -keyname ALDEC08_001 -key keys/ALDEC08_001.pem -in encrypted_file.vhdp -out decrypted_file.vhd
```
It will decrypt file ``encrypted_file.vhdp`` and place it to ``decrypted_file.vhd`` using private key ``keys/ALDEC08_001.pem`` named ``ALDEC08_001``.

## Restrictions and limitations
1. Currently, only encryped VHDL files are supported.
2. There is only one private key leaked (for Aldec, key ALDEC08_001.pem can be found on [electronix forum](http://electronix.ru/forum/lofiversion/index.php/t128531.html)
