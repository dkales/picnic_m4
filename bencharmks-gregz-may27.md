# Benchmarks from pqm4

Run with 
```
make clean && ./benchmarks.py  picnic3l1-dev picnic3l1 picnicl1fs picnicl1full picnicl1ur picnicl3full && ./convert_benchmarks.py md

```
Compiler version:
```
$ arm-none-eabi-gcc --version
arm-none-eabi-gcc (15:9-2019-q4-0ubuntu1) 9.2.1 20191025 (release) [ARM/arm-9-branch revision 277599]
Copyright (C) 2019 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```


# Speed Evaluation
## Key Encapsulation Schemes
| scheme | implementation | key generation [cycles] | encapsulation [cycles] | decapsulation [cycles] |
| ------ | -------------- | ----------------------- | ---------------------- | ---------------------- |
## Signature Schemes
| scheme | implementation | key generation [cycles] | sign [cycles] | verify [cycles] |
| ------ | -------------- | ----------------------- | ------------- | --------------- |
| picnic3l1 (1 executions) | opt | AVG: 64,245 <br /> MIN: 64,245 <br /> MAX: 64,245 | AVG: 309,782,326 <br /> MIN: 309,782,326 <br /> MAX: 309,782,326 | AVG: 205,476,148 <br /> MIN: 205,476,148 <br /> MAX: 205,476,148 |
| picnic3l1 (1 executions) | opt-mem | AVG: 64,247 <br /> MIN: 64,247 <br /> MAX: 64,247 | AVG: 313,872,335 <br /> MIN: 313,872,335 <br /> MAX: 313,872,335 | AVG: 205,378,050 <br /> MIN: 205,378,050 <br /> MAX: 205,378,050 |
| picnic3l1-dev (1 executions) | masked | AVG: 64,265 <br /> MIN: 64,265 <br /> MAX: 64,265 | AVG: 575,091,167 <br /> MIN: 575,091,167 <br /> MAX: 575,091,167 | AVG: 209,724,960 <br /> MIN: 209,724,960 <br /> MAX: 209,724,960 |
| picnic3l1-dev (1 executions) | opt | AVG: 64,244 <br /> MIN: 64,244 <br /> MAX: 64,244 | AVG: 309,771,961 <br /> MIN: 309,771,961 <br /> MAX: 309,771,961 | AVG: 205,502,253 <br /> MIN: 205,502,253 <br /> MAX: 205,502,253 |
| picnic3l1-dev (1 executions) | opt-mem | AVG: 64,247 <br /> MIN: 64,247 <br /> MAX: 64,247 | AVG: 313,894,187 <br /> MIN: 313,894,187 <br /> MAX: 313,894,187 | AVG: 205,412,561 <br /> MIN: 205,412,561 <br /> MAX: 205,412,561 |
| picnicl1fs (1 executions) | opt | AVG: 107,263 <br /> MIN: 107,263 <br /> MAX: 107,263 | AVG: 220,651,422 <br /> MIN: 220,651,422 <br /> MAX: 220,651,422 | AVG: 77,509,968 <br /> MIN: 77,509,968 <br /> MAX: 77,509,968 |
| picnicl1full (1 executions) | opt | AVG: 64,228 <br /> MIN: 64,228 <br /> MAX: 64,228 | AVG: 164,674,248 <br /> MIN: 164,674,248 <br /> MAX: 164,674,248 | AVG: 59,686,096 <br /> MIN: 59,686,096 <br /> MAX: 59,686,096 |
| picnicl1ur (1 executions) | opt | AVG: 107,264 <br /> MIN: 107,264 <br /> MAX: 107,264 | AVG: 251,499,436 <br /> MIN: 251,499,436 <br /> MAX: 251,499,436 | AVG: 95,475,699 <br /> MIN: 95,475,699 <br /> MAX: 95,475,699 |
| picnicl3full (1 executions) | opt | AVG: 93,474 <br /> MIN: 93,474 <br /> MAX: 93,474 | AVG: 326,656,388 <br /> MIN: 326,656,388 <br /> MAX: 326,656,388 | AVG: 120,008,706 <br /> MIN: 120,008,706 <br /> MAX: 120,008,706 |
# Memory Evaluation
## Key Encapsulation Schemes
| Scheme | Implementation | Key Generation [bytes] | Encapsulation [bytes] | Decapsulation [bytes] |
| ------ | -------------- | ---------------------- | --------------------- | --------------------- |
## Signature Schemes
| Scheme | Implementation | Key Generation [bytes] | Sign [bytes] | Verify [bytes] |
| ------ | -------------- | ---------------------- | ------------ | -------------- |
| picnic3l1 | opt | 820 | 69,228 | 87,812 |
| picnic3l1 | opt-mem | 828 | 24,676 | 32,436 |
| picnic3l1-dev | masked | 828 | 32,732 | 32,436 |
| picnic3l1-dev | opt | 820 | 32,468 | 32,428 |
| picnic3l1-dev | opt-mem | 828 | 24,676 | 32,436 |
| picnicl1fs | opt | 716 | 4,052 | 4,020 |
| picnicl1full | opt | 820 | 4,140 | 3,556 |
| picnicl1ur | opt | 716 | 4,052 | 4,020 |
| picnicl3full | opt | 812 | 4,396 | 3,756 |
# Hashing Evaluation
## Key Encapsulation Schemes
| Scheme | Implementation | Key Generation [%] | Encapsulation [%] | Decapsulation [%] |
| ------ | -------------- | ------------------ | ----------------- | ----------------- |
## Signature Schemes
| Scheme | Implementation | Key Generation [%] | Sign [%] | Verify [%] |
| ------ | -------------- | ------------------ | -------- | ---------- |
| picnic3l1 | opt | 0.0% | 69.9% | 85.0% |
| picnic3l1 | opt-mem | 0.0% | 70.2% | 85.0% |
| picnic3l1-dev | masked | 0.0% | 54.6% | 85.3% |
| picnic3l1-dev | opt | 0.0% | 69.9% | 85.0% |
| picnic3l1-dev | opt-mem | 0.0% | 70.2% | 85.0% |
| picnicl1fs | opt | 0.0% | 30.6% | 36.0% |
| picnicl1full | opt | 0.0% | 40.9% | 46.6% |
| picnicl1ur | opt | 0.0% | 38.9% | 47.6% |
| picnicl3full | opt | 0.0% | 37.2% | 43.8% |
# Size Evaluation
## Key Encapsulation Schemes
| Scheme | Implementation | .text [bytes] | .data [bytes] | .bss [bytes] | Total [bytes] |
| ------ | -------------- | ------------- | ------------- | ------------ | ------------- |
## Signature Schemes
| Scheme | Implementation | .text [bytes] | .data [bytes] | .bss [bytes] | Total [bytes] |
| ------ | -------------- | ------------- | ------------- | ------------ | ------------- |
| picnic3l1 | opt | 91,876 | 1,092 | 13 | 92,981 |
| picnic3l1 | opt-mem | 93,064 | 1,092 | 13 | 94,169 |
| picnic3l1-dev | masked | 120,211 | 1,092 | 13 | 121,316 |
| picnic3l1-dev | opt | 91,888 | 1,092 | 13 | 92,993 |
| picnic3l1-dev | opt-mem | 93,076 | 1,092 | 13 | 94,181 |
| picnicl1fs | opt | 53,369 | 1,072 | 0 | 54,441 |
| picnicl1full | opt | 103,347 | 1,072 | 0 | 104,419 |
| picnicl1ur | opt | 54,573 | 1,072 | 0 | 55,645 |
| picnicl3full | opt | 103,271 | 1,072 | 0 | 104,343 |

