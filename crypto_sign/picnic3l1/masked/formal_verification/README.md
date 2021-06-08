This directory contains formal verification scripts that can be verified with [`maskVerif`](https://gitlab.com/benjgregoire/maskverif/). Python3 and `maskVerif` are required to run the scripts.

## How to use `gen_gadgets.py`
```
python3 gen_gadgets.py -N <MPC players> -n <LowMC block size in bits (must be a multiple of 3)> -r <LowMC rounds> -d <masking order> -t <"PICIC" or "KKW">
```

### Example
```
python3 gen_gadgets.py -N 4 -n 9 -r 2 -d 1 -t PICNIC # generate first-order masked PICNIC instance with small block size
maskverif < PICNIC_N4_n9_r2_d1.mv # run maskverif on generated script
python3 gen_gadgets.py -N 4 -d 2 -t KKW # generate second-order masked KKW AND OFFLINE/ONLINE instances (parameters n and r are ignored)
maskverif < KKW_N4_d2.mv # run maskverif on generated script 
```
