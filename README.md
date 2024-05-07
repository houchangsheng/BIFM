# BIFM
- BIFM: Detecting Payload Variants for Network Forensics using Bitmap Index Table and Fuzzy Matching

## AppSketch
- AppSketch interface for IP-Trace data

### Files
- libprotoident: Libprotoident library related files
- AppSketch.h: the implementation of AppSketch
- USS.h: the implementation of USS
- DMatrix.h: the implementation of DMatrix
- WavingSketch.h: the implementation of WavingSketch
- HeavyGuardian.h: the implementation of HeavyGuardian
- ColdFilter.h: the implementation of Cold Filter
- BenchMark.h: the interface of traffic analysis using AppSketch and other methods
- main.cpp: the experiments on AppSketch and other methods

### Compile and Run
- Compile with make
```
$ make
```
- Run the examples, and the program will output some statistics about the accuracy and efficiency. 
```
$ ./appsketch
```
- Note that you can change the configuration of BIFM and other methods.
