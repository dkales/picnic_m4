# Implementations

For Picnic-L1-{FS,full} we provide two variants for low memory scenarios:

* `opt`: based on the optimized C implementation which is compatible with the Picnic specification
* `lowmem-mod`: based on the optimized C implementation but with modifications to `H3` and the seeds and salt generation as discussed below.  This implementation deviates from the specification, and demonstrates the performance improvements of these tweaks. 

For Picnic3-L1 we provide three variants:

* `opt`: a port of the optimized C implementation which is compatible with the
  Picnic specification, modified to use less memory, so as to fit in the
  available RAM of the STM32F4 (128KB)
* `opt-mem`: similar to `opt`, but makes some tradeoffs to reduce memory even
  further, such as not storing the whole Merkle tree in memory, and recomputing
  it as needed. Currently, only signing is optimized to use less RAM,
  verification is the same as `opt`. None of the changes break compatibility with the
  Picnic specification.
* `masked`: This is the masked implementation designed and analyzed in the paper 
  [Side-Channel Protections for Picnic Signatures](https://eprint.iacr.org/2021/735).
  It aims to provide first order protection against probing side-channel attacks.  See 
  the paper for description and analysis of the countermeasures.

## Adaptation of Picnic-L{1,3,5}-{FS,full} to low memory scenarios

### Changes to `H3`

The implementations of Picnic-L{1,3,5}-{FS,full} all require relatively large chunks of memory during both signing and verification. The reason for that is simple: the challenge is computed as 

`H_3(output_shares[1] || ... || output_shares[t] || commitments[1] || ... || commitments[t] || pk || salt || msg)`

 whereas the individual commitments are produced by computing `H_0(H_4(seed) || input_shares[j][i] || views[j][i] || output_shares[j][i])` (`i`-th commitment for round `j`). Without computing the output shares multiple times, the obvious approach to compute all this values is to first compute all input shares, views and output shares and store all these values in memory. In the next step, one would then compute all the commitments. Then, the challenge can simply be computed in one go. Since all the values are stored, it's also straight forward to serialize the signature based on the challenge.

Both the reference implementation and the optimized implementation follow this approach. If the available memory is limited, storing the values throughout the whole signing and verification process is not desirable. Instead of caching all input and output shares, views and commitments, one could instead take the following approach:

1. Set up a SHAKE instance for `H_3`.
1. For each round, produce the output shares and immediately process them with H_3.
1. Starting from the beginning, for each round produce input shares, output shares and views. From that compute the commitment and immediately process them with H_3.
1. Also process pk, salt and msg with H3 and finish the computation of the challenge.
1. Once again, starting from the first round, compute input shares, views, output shares, and commitments and serialize them based on the challenge.

With this approach, the full MPC-in-the-head computations have to repeated three times. By changing the order the arguments passed to `H_3` it is possible to reduce it to only two repetitions, though [WHS20]: instead of first hashing all output shares and then all commitments, the inputs are changed to hash the output shares and commitments per round. That is, the challenge is computed as 

`H_3(output_shares[1] || commitments[1] || ... || output_shares[t] || commitments[t] || pkg || salt || msg)`.

Thereby it is possible to merge steps 2. and 3. into one:

1. Set up a SHAKE instance for `H_3`.
1. For each round produce input shares, output shares and views. From that compute the commitments and process output shares and commitments with H_3.
1. Also process pk, salt and msg with H3 and finish the computation of the challenge.
1. Starting from the first round, compute input shares, views, output shares, and commitments and serialize them based on the challenge.

For the memory optimized implementation of Picnic-L1-{FS,full} in this repository, we have implemented this change to the order of the arguments. This change allows us to get rid of all dynamic memory allocations and reduces the overall stack usage below the memory limits of embedded devices with only some KBs of RAM.

### Changes to seeds and salt generation

Storing seeds for all the rounds requires more than 10 KB for all Picnic-L1 instances. If one does not want to store all seeds in memory (they can easily be recomputed for each round), this however also means that for the generation of the salt, one needs to generate all seeds without storing them. This process wastes many cycles due to the relatively high number of SHAKE permutations required to compute the seeds. In order to avoid these wasted cycles, we switch the order seeds and salt in the output of SHAKE.


## References

* [WHS20] Johannes Winkler, Andrea Höller, Christian Steger: Optimizing Picnic for Limited Memory Resources. DSD 2020. https://doi.org/10.1109/DSD51259.2020.00041
