## Louisiana Cyber Investigators Alliance (LCIA) - www.la-safe.org
 Developed by: Darrell Miller : darrell.miller@la.gov

Simple script that creates simple yara rules for volcano for identifying IoC's a csv file.

```
usage: yara-gen.py [-h] -i INPUT -o OUTPUT [-rn RULENAME]

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        input csv file, format: type,indicator
  -o OUTPUT, --output OUTPUT
                        output file name for yara rule
  -rn RULENAME, --rulename RULENAME
                        custom rule name, default is filename of input file
```

Example:
```
-- no rule name, rule name defaults to input name without .csv
%> python yara-gen.py --input LCIA-Case2309321.csv --output LCIA-Case2309321.yara 

-- custom rule name added
%> python yara-gen.py --input output.csv --output LCIA-Case2309321.yara --rulename LCIA-Case2309321

output of both:

/* 
 Louisiana Cyber Investigators Alliance (LCIA) - www.la-safe.org 
 developed by: Darrell Miller : darrell.miller@la.gov 
 Purpose: simple script to turn a csv in the format: <indicator type>, <indicator> into a yara rule. 
     	 example: 'ipv4, 192.168.1.1' , one type and indicator per line 
 */

LCIA-Case2309321 { 
	strings: 
			$ip1="102.189.34.123"
			$ip2="102.189.9.45"
			$ip3="103.109.100.222"
			$ip4="103.21.221.175"
			$ip5="104.200.67.156"
			$ip6="104.200.67.244"
			$ip7="104.200.73.239"
	condition:
			 any of them
}