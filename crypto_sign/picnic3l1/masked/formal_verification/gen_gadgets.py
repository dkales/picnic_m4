import os
import argparse
import subprocess
import sys

def create_argument_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-N", "--Parties", type=int, default=4, help="number of MPC parties")
    parser.add_argument("-n", "--Nbits", type=int, default=9, help="LowMC block size in bits")
    parser.add_argument("-r", "--Round", type=int, default=2, help="number of LowMC rounds")
    parser.add_argument("-d", "--Maksing", type=int, default=1, help="masking order")
    parser.add_argument("-t", "--Type", type=str, default='PICNIC', help="KKW or PICNIC")
    parser.add_argument("-f", "--Write_To_File",type=int,default=1,help="write to a file")
    return parser

parser    = create_argument_parser()
arguments = parser.parse_args()
N         = arguments.Parties
n         = arguments.Nbits
r         = arguments.Round
d         = arguments.Maksing 
t         = arguments.Type
f         = arguments.Write_To_File

if t != "PICNIC" and t != "KKW":
    print("algorithm type %s is not supported" % t)

fname = ""
if t == "PICNIC":
    print("generating masked PICNIC MPC..")
    fname += t + '_N'+ str(N) + '_n' + str(n) + '_r'+ str(r) + '_d'+ str(d) + '.mv'
if t == "KKW":
    print("generating masked KKW AND..")
    fname += t + '_N'+ str(N) + '_d'+ str(d) + '.mv'
    
if(f==1):
    sys.stdout = open(fname, "w")

    
# -------------------- REFM --------------------
print("(* Multiplication-based refresh *)")
print("proc REFM:")
print(" inputs: x[0:%d]" % d)
print(" outputs: y[0:%d]" % d)
print(" randoms: ", end='')
for i in range(0,d):
    for j in range(i+1,d+1):
        print("r%d%d" % (i, j), end='')
        if i == d-1 and j == d:
            print(";")
        else:
            print(", ", end='')

for i in range(0,d+1):
    print("  y[%d] := x[%d];" % (i,i))

for i in range(0,d):
    for j in range(i+1,d+1):
        print("  y[%d] := y[%d] + r%d%d;" % (i,i,i,j))
        print("  y[%d] := y[%d] + r%d%d;" % (j,j,i,j))
print("end")
print("")

# -------------------- AND --------------------
print("(* SNI secure AND *)")
print("proc AND:")
print(" inputs: a[0:%d], b[0:%d]" % (d,d))
print(" outputs: c[0:%d]" % d)
print(" randoms: ", end='')
for i in range(0,d):
    for j in range(i+1,d+1):
        print("r%d%d" % (i, j), end='')
        if i == d-1 and j == d:
            print(";")
        else:
            print(", ", end='')

for i in range(0,d+1):
    print("  c[%d] := a[%d] * b[%d];" % (i,i,i))

for i in range(0,d):
    for j in range(i+1,d+1):
        print("  c[%d] := c[%d] + r%d%d;" % (i,i,i,j))
        print("  a%d_b%d := a[%d] * b[%d];" % (i,j,i,j))
        print("  a%d_b%d := a[%d] * b[%d];" % (j,i,j,i))
        print("  r%d%d := a%d_b%d + r%d%d;" % (j,i,i,j,i,j))
        print("  r%d%d := r%d%d   + a%d_b%d;" % (j,i,j,i,j,i))
        print("  c[%d] := c[%d] + r%d%d;" % (j,j,j,i))
print("end")
print("")

# -------------------- PARITY_N --------------------
print("(* Compute parity of N shares*)")
print("proc PARITY_N:")
print("  inputs: ", end='')
for i in range(1,N):
    print("in%d_[0:%d]" % (i, d), end=',') 
print("in%d_[0:%d]" % (N, d))

print("  outputs: ", end='')
print("out[0:%d];" % d)

print("  out := in1_ + in2_;")

for i in range(3,N+1):
    print("  out := out + in%d_;" % i)

print("end")
print("")

# -------------------- PARITY_Nm1 --------------------
print("(* Compute parity of N-1 shares*)")
print("proc PARITY_Nm1:")
print("  inputs: ", end='')
for i in range(1,N-1):
    print("in%d_[0:%d]" % (i, d), end=',') 
print("in%d_[0:%d]" % (N-1, d))

print("  outputs: ", end='')
print("out[0:%d];" % d)

print("  out := in1_ + in2_;")

for i in range(3,N):
    print("  out := out + in%d_;" % i)

print("end")
print("")

# -------------------- KKW mode --------------------
if t == "KKW":
    # --------------------  KKW_AND_OFFLINE --------------------
    print("proc KKW_AND_OFFLINE:")
    print("  inputs: ", end='')
    for j in range(1,N+1):
        print("lx%d_[0:%d], " % (j,d), end='')
    for j in range(1,N+1):
        print("ly%d_[0:%d], " % (j,d), end='')    
    for j in range(1,N-1):
        print("lxy%d_[0:%d], " % (j,d), end='')  
    print("lxy%d_[0:%d]" % (N-1,d))  
        
    print("  outputs: ", end='')
    print("lxy%d_[0:%d] " % (N,d))
    
    print("  shares: ", end='')
    print("lx[0:%d], " % d, end='')
    print("ly[0:%d], " % d, end='')
    print("lxyNm1[0:%d], " % d, end='')
    print("lxy[0:%d]; " % d)
    print("")
        
    print("lx = PARITY_N(", end='')
    for j in range(1,N):
        print("lx%d_, " % j, end='')
    print("lx%d_ );" % N)
    
    print("ly = PARITY_N(", end='')
    for j in range(1,N):
        print("ly%d_, " % j, end='')
    print("ly%d_ );" % N)
    
    print("lxy = AND(lx, ly);")
    
    print("lxyNm1 = PARITY_Nm1(", end='')
    for j in range(1,N-1):
        print("lxy%d_, " % j, end='')
    print("lxy%d_ );" % (N-1))
    
    print("lxy%d_ := lxy + lxyNm1;" % N)
    
    print("end")
    print("")

    # -------------------- KKW_AND_ONLINE --------------------
    print("proc KKW_AND_ONLINE:")
    print("  inputs: ", end='')
    print("hx[0:%d], " % d, end='')
    print("hy[0:%d], " % d, end='')
    for j in range(1,N+1):
        print("lx%d_[0:%d], " % (j, d), end='')
    for j in range(1,N+1):
        print("ly%d_[0:%d], " % (j, d), end='')
    for j in range(1,N+1):
        print("lz%d_[0:%d], " % (j, d), end='')
    for j in range(1,N):
        print("lxy%d_[0:%d], " % (j, d), end='')
    print("lxy%d_[0:%d]" % (N, d))

    print("  outputs: ", end='')
    print("hz[0:%d], " % d, end='')
    for j in range(1,N):
        print("s%d_[0:%d], " % (j, d), end='')
    print("s%d_[0:%d]" % (N, d))

    print("  shares: ", end='')
    for j in range(1,N+1):
        print("a%d_[0:%d], " % (j, d), end='')
    for j in range(1,N+1):
        print("b%d_[0:%d], " % (j, d), end='')
    print("c[0:%d], " % d, end='')
    print("s[0:%d];" % d)
    print("")

    ## Process starts here
    for j in range(1,N+1):
        print("(* compute broadcast messages of party %d *)" % j)
        print("a%d_ = AND(hx, ly%d_);" % (j, j))
        print("b%d_ = AND(hy, lx%d_);" % (j, j))
        print("s%d_ := lz%d_ + lxy%d_;" % (j, j, j))
        print("s%d_ := s%d_ + a%d_;" % (j, j, j))
        print("s%d_ := s%d_ + b%d_;" % (j, j, j))
        print("")

    print("c = AND(hx, hy);")

    
    print("s = PARITY_N(", end='')
    for j in range(1,N):
        print("s%d_, " % j, end='')
    print("s%d_ );" % N)
    
    print("hz := c + s;")
    print("end")
    print("")
    
    #print('para noglitch SNI REFM')
    #print('para noglitch SNI AND')
    print('para noglitch SNI KKW_AND_OFFLINE')
    print('para noglitch SNI KKW_AND_ONLINE')
    
    if(f==1):
        sys.stdout.close()
    sys.exit()


# -------------------- PICNIC mode --------------------
# -------------------- AFFINE --------------------
print("(* Affine layer gadget *)")
print("proc AFFINE:")
print("  inputs: ", end='')
for i in range(1,n):
    print("st%d_[0:%d]" % (i, d), end=',') 
print("st%d_[0:%d]" % (n, d))

print("  outputs: ", end='')
for i in range(1,n):
    print("a%d_[0:%d]" % (i, d), end=',')
print("a%d_[0:%d];" % (n, d))

for i in range(1,n+1):
    print("  a%d_ := st1_ + st2_;" % i)
    for j in range(3,n+1):
        print("  a%d_ := a%d_ + st%d_;" % (i,i,j))

print("end")
print("")


# -------------------- PICNIC_AND_OFFLINE --------------------
print("proc PICNIC_AND_OFFLINE:")
print("  inputs: ", end='')
print("lx[0:%d], " % d, end='')
print("ly[0:%d], " % d, end='')
print("lz[0:%d], " % d, end='')
for j in range(1,N-1):
    print("helper_P%d_[0:%d], " % (j, d), end='')
print("helper_P%d_[0:%d]" % (N-1, d))

print("  outputs: ", end='')
print("helper_P%d_[0:%d]" % (N, d))

print("  shares: ", end='')
print("helper_Nm1[0:%d], " % d, end='')
print("lxy[0:%d];" % d)

## Process starts here
print("helper_Nm1 = PARITY_Nm1(", end='')
for j in range(1,N-1):
    print("helper_P%d_, " % j, end='')
print("helper_P%d_);" % (N-1))

print("lxy = AND(lx, ly);")
print("helper_P%d_ := lxy + helper_Nm1;" % N)
print("helper_P%d_ := helper_P%d_ + lz;" % (N, N))

print("end")
print("")

# -------------------- SBOX_OFFLINE --------------------
print("proc SBOX_OFFLINE:")
print("  inputs: ", end='')
print("lc[0:%d], " % d, end='')
print("lb[0:%d], " % d, end='')
print("la[0:%d], " % d, end='')
print("lf[0:%d], " % d, end='')
print("le[0:%d], " % d, end='')
print("ld[0:%d], " % d, end='')
for j in range(1,N-1):
    print("helper_P%d_ab[0:%d], " % (j, d), end='')
    print("helper_P%d_ca[0:%d], " % (j, d), end='')
    print("helper_P%d_bc[0:%d], " % (j, d), end='')
    
print("helper_P%d_ab[0:%d], " % (N-1, d), end='')
print("helper_P%d_ca[0:%d], " % (N-1, d), end='')
print("helper_P%d_bc[0:%d]  " % (N-1, d))

print("  outputs: ", end='')
print("helper_P%d_ab[0:%d], " % (N, d), end='')
print("helper_P%d_ca[0:%d], "  % (N, d), end='')
print("helper_P%d_bc[0:%d]  " % (N, d))

print("  shares: ", end='')
print("lzab[0:%d], " % d, end='')
print("lzca[0:%d], " % d, end='')
print("lzbc[0:%d]; " % d)

## Process starts here
print("lzab := lf + la;")
print("lzab := lzab + lb;")
print("lzab := lzab + lc;")

print("lzbc := ld + la;")

print("lzca := le + la;")
print("lzca := lzca + lb;")

### helper_PN_ab
print("helper_P%d_ab = PICNIC_AND_OFFLINE(la, lb, lzab, " % N, end='')
for j in range(1,N-1):
    print("helper_P%d_ab, " % j, end='')
print("helper_P%d_ab);" % (N-1))

### helper_PN_bc
print("helper_P%d_bc = PICNIC_AND_OFFLINE(lb, lc, lzbc, " % N, end='')
for j in range(1,N-1):
    print("helper_P%d_bc, " % j, end='')
print("helper_P%d_bc);" % (N-1))

### helper_PN_ca
print("helper_P%d_ca = PICNIC_AND_OFFLINE(lc, la, lzca, " % N, end='')
for j in range(1,N-1):
    print("helper_P%d_ca, " % j, end='')    
print("helper_P%d_ca);" % (N-1))

print("end")
print("")


# -------------------- LOWMC_ROUND_OFFLINE --------------------
print("proc LOWMC_ROUND_OFFLINE:")
print("  inputs: ", end='')
for i in range(1,n):
    print("lsk_%d_[0:%d], " % (i, d), end='')
print("lsk_%d_[0:%d], " % (n, d), end='')

for i in range(1,n):
    print("prstin_%d_[0:%d], " % (i, d), end='')
print("prstin_%d_[0:%d], " % (n, d), end='')

for i in range(1,n):
    print("stin_%d_[0:%d], " % (i, d), end='')
print("stin_%d_[0:%d], " % (n, d), end='')

## N-1 helpers
for i in range(1,n+1):
    for j in range(1, N):
        print("helper_P%d_%d_[0:%d]" % (j, i, d),  end='')
        if i == n and j == N-1:
            print("")
        else:
            print(", ", end='')
print("")
    
print("  outputs: ", end='')
## Nth party helpers
for i in range(1,n+1):
    print("helper_P%d_%d_[0:%d]" % (N, i, d), end='')
    if i == n:
        print("")
    else:
        print(", ", end='')
print("")

print("  shares: ", end='')
for i in range(1,n):
    print("stout_%d_[0:%d], " % (i, d), end='')
print("stout_%d_[0:%d], " % (n, d), end='')

for i in range(1,n):
    print("stouttmp_%d_[0:%d], " % (i, d), end='')
print("stouttmp_%d_[0:%d], " % (n, d), end='')

for i in range(1,n):
    print("rk_%d_[0:%d], " % (i, d), end='')
print("rk_%d_[0:%d]" % (n, d), end='')
print(";")

## Process starts here

### key update
print("(", end='')
for i in range(1,n):
    print("rk_%d_, " % i, end='')
print("rk_%d_) = AFFINE(" % n, end='')
for i in range(1,n):
    print("lsk_%d_, " % i, end='')
print("lsk_%d_);" % n)

for i in range(1,n+1):
    print("stouttmp_%d_ := prstin_%d_ + rk_%d_;" % (i, i, i))
    
### linear layer
print("(", end='')
for i in range(1,n):
    print("stout_%d_, " % i, end='')
print("stout_%d_) = AFFINE(" % n, end='')
for i in range(1,n):
    print("stouttmp_%d_, " % i, end='')
print("stouttmp_%d_);" % n)

### s-box layer
for i in range(0,n//3):
    print("(helper_P%d_%d_, helper_P%d_%d_, helper_P%d_%d_) = SBOX_OFFLINE(" % (N, 3*i+1, N, 3*i+2, N, 3*i+3), end='')
    print("stin_%d_, stin_%d_, stin_%d_, " % (3*i+1, 3*i+2, 3*i+3), end='')
    print("stout_%d_, stout_%d_, stout_%d_, " % (3*i+1, 3*i+2, 3*i+3), end='')
    for j in range(1, N-1):
        print("helper_P%d_%d_, helper_P%d_%d_, helper_P%d_%d_, " % (j, 3*i+1, j, 3*i+2, j, 3*i+3), end='')
    print("helper_P%d_%d_, helper_P%d_%d_, helper_P%d_%d_);" % (N-1, 3*i+1, N-1, 3*i+2, N-1, 3*i+3))
print("end")
print("")


# -------------------- PICNIC_OFFLINE --------------------
print("proc PICNIC_OFFLINE:")
print("  inputs: ", end='')
for k in range(1,r+1):
    for i in range(1,n+1):
        for j in range(1, N+1):
            print("r%d_tape_P%d_%d_[0:%d], " % (k, j, i, d), end='')
    print("")
print("")
for k in range(1,r+1):
    for i in range(1,n+1):
        for j in range(1, N):
            print("r%d_helper_P%d_%d_[0:%d], " % (k, j, i, d), end='')
    print("")
print("")

for i in range(1,n):
    print("r%d_stin_%d_[0:%d], " % (r+1, i, d) , end='')
print("r%d_stin_%d_[0:%d]" % (r+1, n, d))
print("")

print("  outputs: ", end='')
for k in range(1,r+1):
    for i in range(1,n+1):
        print("r%d_helper_P%d_%d_[0:%d], " % (k, N, i, d), end='')
    print("")
print("")

for i in range(1,n):
    print("lsk_%d_[0:%d], " % (i,d) , end='')
print("lsk_%d_[0:%d]" % (n,d) , end='')
print("")


print("  shares: ", end='')
for i in range(1,n+1):
    print("r0_rk_%d_[0:%d], " % (i, d), end='')

for k in range(1,r+1):
    for i in range(1,n+1):
        print("r%d_stin_%d_[0:%d] " % (k, i, d), end='')
        if k == r and i == n:
            print(";")
        else:
            print(", ", end='')
    print("")
print("")


# Process starts here

## extract initial key
print("(* extract initial key *)")
for i in range(1,n+1):
    print("r0_rk_%d_ = PARITY_N(" % i, end='')
    for j in range(1,N):
        print("r1_tape_P%d_%d_, " % (j, i), end='')
    print("r1_tape_P%d_%d_);" % (N, i))

print("(* re-compute secret key masks: lsk = K^-1*r0_rk *)")
print("(", end='')
for i in range(1,n):
    print("lsk_%d_, " % i , end='')
print("lsk_%d_) = AFFINE(" % n, end='')
for i in range(1,n):
    print("r0_rk_%d_, " % i , end='')
print("r0_rk_%d_);" % n)
print("")

k = r

while k > 0:
    print("(* round %d *)" % k)
    if k == 1:
        for i in range(1,n+1):
            print("r%d_stin_%d_ := r0_rk_%d_;" % (k, i, i))
    else:
        for i in range(1,n+1):
            print("r%d_stin_%d_ = PARITY_N(" % (k, i), end='')
            for j in range(1,N):
                print("r%d_tape_P%d_%d_, " % (k, j, i), end='')
            print("r%d_tape_P%d_%d_);" % (k, N, i))

    print("(", end='')
    for i in range(1,n):
        print("r%d_helper_P%d_%d_, " % (k, N, i), end='')
    print("r%d_helper_P%d_%d_) = LOWMC_ROUND_OFFLINE(" % (k, N, n), end='')
    for i in range(1,n+1):
        print("lsk_%d_, " % i , end='')
    # previous stin
    for i in range(1,n+1):
        print("r%d_stin_%d_, " % (k+1, i) , end='')
    # current stin
    for i in range(1,n+1):
        print("r%d_stin_%d_, " % (k, i) , end='')
    # helper for N-1 parties
    for i in range(1,n+1):
        for j in range(1, N):
            print("r%d_helper_P%d_%d_" % (k, j, i), end='')
            if i == n and j == N-1:
                print(");")
            else:
                print(", ", end='')
    print("")
            
    k = k - 1

print("end")
print("")


# -------------------- PICNIC_AND_ONLINE --------------------
print("proc PICNIC_AND_ONLINE:")
print("  inputs: ", end='')
print("hx[0:%d], " % d, end='')
print("hy[0:%d], " % d, end='')
for j in range(1,N+1):
    print("lx_%d_[0:%d], " % (j, d), end='')
for j in range(1,N+1):
    print("ly_%d_[0:%d], " % (j, d), end='')
for j in range(1,N):
    print("helper_P%d_[0:%d], " % (j, d), end='')
print("helper_P%d_[0:%d]" % (N, d))

print("  outputs: ", end='')
print("hz[0:%d], " % d, end='')
for j in range(1,N):
    print("s_%d_[0:%d], " % (j, d), end='')
print("s_%d_[0:%d]" % (N, d))

print("  shares: ", end='')
for j in range(1,N+1):
    print("a_%d_[0:%d], " % (j, d), end='')
for j in range(1,N+1):
    print("b_%d_[0:%d], " % (j, d), end='')
print("c[0:%d], " % d, end='')
print("s[0:%d];" % d)
print("")
    
## Process starts here
for j in range(1,N+1):
    print("a_%d_ = AND(hx, ly_%d_);" % (j, j))
    print("b_%d_ = AND(hy, lx_%d_);" % (j, j))
    print("s_%d_ := a_%d_ + b_%d_;" % (j, j, j))
    print("s_%d_ := s_%d_ + helper_P%d_;" % (j, j, j))

print("c = AND(hx, hy);")

print("s := s_1_ + s_2_;")
for j in range(3,N+1):
    print("s := s + s_%d_;" % j)
print("hz := c + s;")

print("end")
print("")


# -------------------- SBOX_ONLINE --------------------
print("proc SBOX_ONLINE:")
print("  inputs: ", end='')
print("hc[0:%d], " % d, end='')
print("hb[0:%d], " % d, end='')
print("ha[0:%d], " % d, end='')
for j in range(1,N+1):
    print("lc_%d_[0:%d], " % (j, d), end='')
    print("lb_%d_[0:%d], " % (j, d), end='')
    print("la_%d_[0:%d], " % (j, d), end='')
    
for j in range(1,N):
    print("helper_P%d_ab[0:%d], " % (j, d), end='')
    print("helper_P%d_ca[0:%d], " % (j, d), end='')
    print("helper_P%d_bc[0:%d], " % (j, d), end='')
    
print("helper_P%d_ab[0:%d], " % (N, d), end='')
print("helper_P%d_ca[0:%d], " % (N, d), end='')
print("helper_P%d_bc[0:%d]  " % (N, d))

print("  outputs: ", end='')
print("hf[0:%d], " % d, end='')
print("he[0:%d], " % d, end='')
print("hd[0:%d], " % d, end='')
for j in range(1,N+1):
    print("s_ab_%d_[0:%d], " % (j, d), end='')
for j in range(1,N+1):
    print("s_ca_%d_[0:%d], " % (j, d), end='')
for j in range(1,N):
    print("s_bc_%d_[0:%d], " % (j, d), end='')
print("s_bc_%d_[0:%d] " % (N, d))

print("  shares: ", end='')
print("hab[0:%d], " % d, end='')
print("hca[0:%d], " % d, end='')
print("hbc[0:%d] " % d, end='')
print(";")

## Process starts here
### hat ab
print("(hab, ", end='')
for j in range(1,N):
    print("s_ab_%d_, " % j, end='')
print("s_ab_%d_) = PICNIC_AND_ONLINE(ha, hb, " % N, end='')
for j in range(1,N+1):
    print("la_%d_, " % j, end='')
for j in range(1,N+1):
    print("lb_%d_, " % j, end='')
for j in range(1,N):
    print("helper_P%d_ab, " % (j), end='')
print("helper_P%d_ab);" % (N))
print("")

### hat bc
print("(hbc, ", end='')
for j in range(1,N):
    print("s_bc_%d_, " % j, end='')
print("s_bc_%d_) = PICNIC_AND_ONLINE(hb, hc, " % N, end='')
for j in range(1,N+1):
    print("lb_%d_, " % j, end='')
for j in range(1,N+1):
    print("lc_%d_, " % j, end='')
for j in range(1,N):
    print("helper_P%d_bc, " % j, end='')
print("helper_P%d_bc);" %  N)
print("")

### hat ca
print("(hca, ", end='')
for j in range(1,N):
    print("s_ca_%d_, " % j, end='')
print("s_ca_%d_) = PICNIC_AND_ONLINE(hc, ha, " % N, end='')
for j in range(1,N+1):
    print("lc_%d_, " % j, end='')
for j in range(1,N+1):
    print("la_%d_, " % j, end='')
for j in range(1,N):
    print("helper_P%d_ca, " % (j), end='')
print("helper_P%d_ca);" % (N))
print("")

# hat f
print("hf := ha + hb;")
print("hf := hf + hc;")
print("hf := hf + hab;")

# hat e
print("he := ha + hb;")
print("he := he + hca;")

# hat d
print("hd := ha + hbc;")

print("end")
print("")


# -------------------- LOWMC_ROUND_ONLINE --------------------
print("proc LOWMC_ROUND_ONLINE:")
print("  inputs: ", end='')
for i in range(1,n+1):
    print("hsk_%d_[0:%d], " % (i, d), end='')
print("")
for i in range(1,n+1):
    print("stin_%d_[0:%d], " % (i, d), end='')
print("")
for i in range(1,n+1):
    for j in range(1,N+1):
        print("tape_P%d_%d_[0:%d], " % (j, i, d), end='')
    
for i in range(1,n+1):
    for j in range(1,N+1):
        print("helper_P%d_%d_[0:%d]" % (j, i, d), end='')
        if i == n and j == N:
            print("")
        else:
            print(", ", end='')
    
print("")
    
print("  outputs: ", end='')
for i in range(1,n+1):
    print("stout_%d_[0:%d], " % (i, d), end='')
print("")

for i in range(1,n+1):
    for j in range(1,N+1):
        print("msgs_P%d_%d_[0:%d]" % (j, i, d), end='')
        if i == n and j == N:
            print("")
        else:
            print(", ", end='')
    
print("")

print("  shares: ", end='')
for i in range(1,n+1):
    print("sbout_%d_[0:%d], " % (i, d), end='')
print("")

for i in range(1,n+1):
    print("mmout_%d_[0:%d], " % (i, d), end='')
print("")

for i in range(1,n+1):
    print("rk_%d_[0:%d], " % (i, d), end='')
print("")
    
for i in range(1,n+1):
    print("stouttmp_%d_[0:%d] " % (i, d), end='')
    if i == n:
        print("")
    else:
        print(", ", end='')

print(";")

## Process starts here
### s-box layer
print("(* sbox layer *)")
for i in range(0,n//3):
    print("(sbout_%d_, sbout_%d_, sbout_%d_, " % (3*i+1, 3*i+2, 3*i+3), end='')
    for j in range(1,N+1):
        print("msgs_P%d_%d_, " % (j, 3*i+1), end='')
    for j in range(1,N+1):
        print("msgs_P%d_%d_, " % (j, 3*i+2), end='')
    for j in range(1,N):
        print("msgs_P%d_%d_, " % (j, 3*i+3), end='')
    print("msgs_P%d_%d_) = SBOX_ONLINE(" % (N, 3*i+3), end='')
    
    print("stin_%d_, stin_%d_, stin_%d_, " % (3*i+1, 3*i+2, 3*i+3), end='')
    for j in range(1,N+1):
        print("tape_P%d_%d_, " % (j, 3*i+1), end='')
        print("tape_P%d_%d_, " % (j, 3*i+2), end='')
        print("tape_P%d_%d_, " % (j, 3*i+3), end='')
    
    for j in range(1,N):
        print("helper_P%d_%d_, " % (j, 3*i+1), end='')
        print("helper_P%d_%d_, " % (j, 3*i+2), end='')
        print("helper_P%d_%d_, " % (j, 3*i+3), end='')
    print("helper_P%d_%d_, " % (N, 3*i+1), end='')
    print("helper_P%d_%d_, " % (N, 3*i+2), end='')
    print("helper_P%d_%d_ );" % (N, 3*i+3))
    print("")
    
### affine layer
print("(* affine layer *)")
print("(", end='')
for i in range(1,n):
    print("mmout_%d_, " % i , end='')
print("mmout_%d_) = AFFINE(" % n, end='')
for i in range(1,n):
    print("sbout_%d_, " % i , end='')
print("sbout_%d_);" % n)
print("")

### key update
print("(* key update *)")
print("(", end='')
for i in range(1,n):
    print("rk_%d_, " % i , end='')
print("rk_%d_) = AFFINE(" % n, end='')
for i in range(1,n):
    print("hsk_%d_, " % i , end='')
print("hsk_%d_);" % n)
print("")

## state update
print("(* state update *)")
for i in range(1,n+1):
    print("(* without refresh the gadget is not NI*)")
    #print("stout_%d_ := mmout_%d_ + rk_%d_;" % (i, i, i))
    print("stouttmp_%d_ := mmout_%d_ + rk_%d_;" % (i, i, i))
    print("stout_%d_ = REFM(stouttmp_%d_);" % (i, i))
    
print("end")
print("")


# -------------------- PICNIC_ONLINE --------------------
print("proc PICNIC_ONLINE:")
print("  inputs: ", end='')
for i in range(1,n+1):
    print("hsk_%d_[0:%d], " % (i,d) , end='')
print("")
for k in range(1,r+1):
    for i in range(1,n+1):
        for j in range(1,N+1):
            print("r%d_tape_P%d_%d_[0:%d], " % (k, j, i, d), end='')    
print("")
for k in range(1,r+1):
    for i in range(1,n+1):
        for j in range(1,N+1):
            print("r%d_helper_P%d_%d_[0:%d] " % (k, j, i, d), end='')
            if k == r and i == n and j == N:
                print("")
            else:
                print(", ", end='')
print("")


print("")

print("  outputs: ", end='')
for k in range(1,r+1):
    for i in range(1,n+1):
        for j in range(1,N+1):
            print("r%d_msgs_P%d_%d_[0:%d], " % (k, j, i, d), end='')
print("")

for i in range(1,n+1):
    print("r%d_stin_%d_[0:%d]" % (r+1, i, d), end='')
    if i == n:
        print("")
    else:
        print(", ", end='')
print("")

print("  shares: ", end='')
for i in range(1,n+1):
    print("r0_rk_%d_[0:%d], " % (i, d) , end='')
for k in range(1,r+1):
    for i in range(1,n+1):
        print("r%d_stin_%d_[0:%d]" % (k, i, d) , end='')
        if k == r and i == n:
            print(";")
        else:
            print(", ", end='')
print("")


# Process starts here
## key init
print("(* key init *)")
print("(", end='')
for i in range(1,n):
    print("r0_rk_%d_, " % i , end='')
print("r0_rk_%d_) = AFFINE(" % n, end='')
for i in range(1,n):
    print("hsk_%d_, " % i , end='')
print("hsk_%d_);" % n)
for i in range(1,n+1):
    print("r1_stin_%d_ = REFM(r0_rk_%d_);" % (i, i))
print("")
## LowMC rounds
for k in range(1,r+1):
    print("(* round %d *)" % k)
    print("(", end='')
    for i in range(1,n+1):
        print("r%d_stin_%d_," % (k+1, i), end='')
    for i in range(1,n+1):
        for j in range(1,N+1):
            print("r%d_msgs_P%d_%d_" % (k, j, i), end='')
            if i == n and j == N:
                print(") = LOWMC_ROUND_ONLINE(", end='')
            else:
                print(", ", end='')
    for i in range(1,n+1):
        print("hsk_%d_, " % i , end='')        
    for i in range(1,n+1):
        print("r%d_stin_%d_, " % (k, i), end='')
    for i in range(1,n+1):
        for j in range(1,N+1):
            print("r%d_tape_P%d_%d_, " % (k, j, i), end='')
    for i in range(1,n+1):
        for j in range(1,N+1):
            print("r%d_helper_P%d_%d_" % (k, j, i), end='')       
            if i == n and j == N:
                print(");")
            else:
                print(", ", end='')
    print("")
                
print("")

print("end")
print("")


# -------------------- PICNIC_MPC --------------------
print("proc PICNIC_MPC:")
print("  inputs: ", end='')
for i in range(1,n+1):
    print("sk_%d_[0:%d], " % (i,d) , end='')
print("")

for k in range(1,r+1):
    for i in range(1,n+1):
        for j in range(1,N+1):
            print("r%d_tape_P%d_%d_[0:%d], " % (k, j, i, d), end='')    
print("")

for k in range(1,r+1):
    for i in range(1,n+1):
        for j in range(1,N):
            print("r%d_helper_P%d_%d_[0:%d], " % (k, j, i, d), end='')            
print("")

print("(* shares of zero vectors *)")
for i in range(1,n):
    print("zero_%d_[0:%d], " % (i, d) , end='')
print("zero_%d_[0:%d]" % (n, d))
print("")


print("  outputs: ", end='')
print("(* offline results to be committed *)")
for k in range(1,r+1):
    for i in range(1,n+1):
        print("r%d_helper_P%d_%d_[0:%d], " % (k, N, i, d), end='')
    print("")
print("")

print("(* online results to be committed *)")
for i in range(1,n+1):
    print("hsk_%d_[0:%d], " % (i, d), end='')
print("")

for k in range(1,r+1):
    for i in range(1,n+1):
        for j in range(1,N+1):
            print("r%d_msgs_P%d_%d_[0:%d], " % (k, j, i, d), end='')
print("")

for i in range(1,n):
    print("r%d_stin_%d_[0:%d], " % (r+1, i, d), end='')
print("r%d_stin_%d_[0:%d] " % (r+1, n, d))
print("")

print("  shares: ", end='')
for i in range(1,n+1):
    print("rsk_%d_[0:%d], " % (i, d) , end='')
print("")

for i in range(1,n):
    print("lsk_%d_[0:%d], " % (i, d), end='')
print("lsk_%d_[0:%d];" % (n, d))
    
print("")


## process starts here
print("(* offline phase *)")
print("(", end='')
for k in range(1,r+1):
    for i in range(1,n+1):
        print("r%d_helper_P%d_%d_, " % (k, N, i), end='')

for i in range(1,n+1):
    print("lsk_%d_" % i, end='')
    if i == n:
        print(") = PICNIC_OFFLINE(")
    else:
        print(", ", end='')
    
for k in range(1,r+1):
    for i in range(1,n+1):
        for j in range(1,N+1):
            print("r%d_tape_P%d_%d_, " % (k, j, i), end='')

for k in range(1,r+1):
    for i in range(1,n+1):
        for j in range(1,N):
            print("r%d_helper_P%d_%d_, " % (k, j, i), end='')

for i in range(1,n):
    print("zero_%d_, " % i , end='')
print("zero_%d_);" % n)
print("")

print("(* refresh & mask secret key *)")
for i in range(1,n+1):
    print("rsk_%d_ = REFM(sk_%d_);" % (i, i))

for i in range(1,n+1):
    print("hsk_%d_ := rsk_%d_ + lsk_%d_;" % (i, i, i))
print("")

print("(* online phase *)")
print("(", end='')
for k in range(1,r+1):
    for i in range(1,n+1):
        for j in range(1,N+1):
            print("r%d_msgs_P%d_%d_, " % (k, j, i), end='')
for i in range(1,n):
    print("r%d_stin_%d_, " % (r+1, i), end='')
print("r%d_stin_%d_) = PICNIC_ONLINE(" % (r+1, n))

for i in range(1,n+1):
    print("hsk_%d_, " % i, end='')
for k in range(1,r+1):
    for i in range(1,n+1):
        for j in range(1,N+1):
            print("r%d_tape_P%d_%d_, " % (k, j, i), end='')
for k in range(1,r+1):
    for i in range(1,n+1):
        for j in range(1,N+1):
            print("r%d_helper_P%d_%d_" % (k, j, i), end='')
            if k == r and i == n and j == N:
                print(");")
            else:
                print(", ", end='')

            
print("end")
print("")

#print('verbose 1')
#print('para noglitch NI AFFINE')
#print('para noglitch SNI PICNIC_AND_OFFLINE')
#print('para noglitch NI SBOX_OFFLINE')
#print('para noglitch NI LOWMC_ROUND_OFFLINE')
print('para noglitch NI PICNIC_OFFLINE')
#print('para noglitch SNI PICNIC_AND_ONLINE')
#print('para noglitch NI SBOX_ONLINE')
#print('para noglitch NI LOWMC_ROUND_ONLINE')
print('para noglitch NI PICNIC_ONLINE')
print('para noglitch NI PICNIC_MPC')

if(f==1):
    sys.stdout.close()
    


