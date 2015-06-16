#!/bin/bash

#Sequence: 10, 11, 12, 13, 22

# Wrong sequence:
echo -n "*" | nc -q1 -u 10.0.0.2 10
echo -n "*" | nc -q1 -u 10.0.0.2 11
echo -n "*" | nc -q1 -u 10.0.0.2 40

# Correct Sequence
echo -n "*" | nc -q1 -u 10.0.0.2 10
echo -n "*" | nc -q1 -u 10.0.0.2 11
echo -n "*" | nc -q1 -u 10.0.0.2 12
echo -n "*" | nc -q1 -u 10.0.0.2 13
nc -u 10.0.0.2 22
