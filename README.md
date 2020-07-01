Instruction Frequency Counter
=========

Instrumentation tool for counting frequency of Intel instructions using Pin.

Usage
-------

Compile
    
    make PIN_ROOT=/path/to/pin

Run
    
    /path/to/pin/pin -t obj-intel64/instruction_freq.so -- /path/to/exec
