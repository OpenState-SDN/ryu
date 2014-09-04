#!/bin/bash

#Sequence: 5123, 6234, 7345, 8456, 2000

# Wrong sequence:
echo -n "*" | nc -q1 -u 10.0.0.2 5123
echo -n "*" | nc -q1 -u 10.0.0.2 6234
echo -n "*" | nc -q1 -u 10.0.0.2 73

# Correct Sequence
echo -n "*" | nc -q1 -u 10.0.0.2 5123
echo -n "*" | nc -q1 -u 10.0.0.2 6234
echo -n "*" | nc -q1 -u 10.0.0.2 7345
echo -n "*" | nc -q1 -u 10.0.0.2 8456
nc -u 10.0.0.2 2000