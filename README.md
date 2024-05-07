# BIFM
- BIFM: Detecting Payload Variants for Network Forensics using Bitmap Index Table and Fuzzy Matching

## BIFM
- Network traffic digesting and malicious traffic traceability tool

### Files
- BIFM: the implementation of BIFM
- CBID: the implementation of CBID
- DSPAS: the implementation of DSPAS
- mrsh_net: the implementation of mrsh-net
- mrsh_cf: the implementation of mrsh-cf

### Compile and Run
- Compile with make
```
$ make
```
- Run BIFM, and the program will output some statistics about the accuracy and efficiency. 
```
$ ./bifm <filter number> <data reduction ratio> <winnowing window> <shingling window> <down sampling threshold> <block hit threshold> <check threshold> <digested traffic> <queried excerpts>
```
- Note that you can change the configuration of BIFM and other methods.
