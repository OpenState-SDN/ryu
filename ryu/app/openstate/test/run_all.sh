declare -A ret_values

for f in *.py;
do
	echo -e "\n\x1b[33m[Testing $f]\x1b[0m";
	sudo python $f;
	ret_values[$f]=$?;
done 

echo -e "\n*******************************************************************\n\nSUMMARY:\n"

for f in *.py;
do
	if [[ ${ret_values[$f]} -eq 1 ]]; then
		echo -e "$f: \x1b[31mFAILED\x1b[0m";
	else
		echo -e "$f: \x1b[32mSUCCEEDED\x1b[0m";
	fi
done 