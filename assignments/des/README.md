# Differential Cryptanalysis of a Custom 6-Round DES

This zip file contains a Python implementation of a differential cryptanalytic
attack on DES reduced to 6 rounds. The implementation is accompanied by a report
describing the implementation.

To run this code, a working installation of Python 3 is required. Install the
required packages by issuing the following command.

```bash
pip install requirements.txt
```

To create the DDTs for all S boxes, run the following command.

```bash
python3 ddt.py
```

To run the key recovery attack, run the following command. Ensure the oracle URL
is correct and running.

```bash
python3 recover.py
```