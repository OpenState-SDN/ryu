#!/bin/bash

echo -n "*" | nc -q1 -u 10.0.0.2 5123
echo -n "*" | nc -q1 -u 10.0.0.2 6234
echo -n "*" | nc -q1 -u 10.0.0.2 73
echo -n "*" | nc -q1 -u 10.0.0.2 5123
echo -n "*" | nc -q1 -u 10.0.0.2 6234
echo -n "*" | nc -q1 -u 10.0.0.2 7345
echo -n "*" | nc -q1 -u 10.0.0.2 8456
nc -u 10.0.0.2 2000