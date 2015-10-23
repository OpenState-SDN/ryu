for f in *.py; do echo -e "\n[Testing \x1b[32m$f\x1b[0m]"; sudo python $f; done
