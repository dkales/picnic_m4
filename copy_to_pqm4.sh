#!/bin/bash

# After updating the picnic_m4 repo, run this script to copy the code into the
# pqm4 project
# Assumes that the directory structure is:
# picnic_m4
# ├── copy_to_pqm4.sh
# ├── crypto_sign
# ├── notes.txt
# └── pqm4


echo "Copying crypto_sign/picnic3l1 to pqm4/crypto_sign"
cp -r crypto_sign/picnic3l1 pqm4/crypto_sign/
cp -r crypto_sign/picnicl1fs pqm4/crypto_sign/
cp -r crypto_sign/picnicl1full pqm4/crypto_sign/
# cp -r crypto_sign/picnicl1ur pqm4/crypto_sign/
# cp -r crypto_sign/picnicl3fs pqm4/crypto_sign/
# cp -r crypto_sign/picnicl3full pqm4/crypto_sign/
# cp -r crypto_sign/picnicl3ur pqm4/crypto_sign/
# cp -r crypto_sign/picnicl5fs pqm4/crypto_sign/
# cp -r crypto_sign/picnicl5full pqm4/crypto_sign/
# cp -r crypto_sign/picnicl5ur pqm4/crypto_sign/
