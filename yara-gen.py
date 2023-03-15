# Louisiana Cyber Investigators Alliance (LCIA) - www.la-safe.org
# developed by: Darrell Miller : darrell.miller@la.gov

# simple script that creates simple yara rules for volcano for identifying IoC's
# a csv file.
# (i often use these scripts as teaching tools, so there is far more documentation than necessary)

import argparse
from os.path import exists

def argParser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="input csv file, format: type,indicator", required=True)
    parser.add_argument("-o", "--output", help="output file name for yara rule", required=True)
    parser.add_argument("-rn", "--rulename", help="custom rule name, default is filename of input file", required=False)
    args = vars(parser.parse_args())
    return args

if __name__ == '__main__':
    LCIAHeader="/* \n Louisiana Cyber Investigators Alliance (LCIA) - www.la-safe.org \n developed by: Darrell Miller : darrell.miller@la.gov \n Purpose: simple script to turn a csv in the format: <indicator type>, <indicator> into a yara rule. \n     \t example: 'ipv4, 192.168.1.1' , one type and indicator per line \n */\n\n"

    args = argParser()

    if exists(args['input']):
        #read text file
        with open(args['input']) as f:
            rawData = f.readlines()

        # remote header from list/file
        rawData.pop(0)

        fileWriter=open(args['output'], 'w')
        fileWriter.write(LCIAHeader)

        if args['rulename']:
            ruleName=args['rulename']
        else:
            ruleName=args['input']
            ruleName=ruleName.replace('.csv','')
            ruleName = ruleName.replace('/', '')
            ruleName = ruleName.replace('_', '')
            ruleName = ruleName.replace(',', '')

        firstLine="rule " + ruleName + " { \n"
        fileWriter.write(firstLine)
        fileWriter.write("\tstrings: \n")

        stringCounter=1

        for item in rawData:
            if item[0]=="#" or len(item) <2 or "type,id" in item: #skipping line, comment statement or header
                continue
            else:
                item=item.strip() #removes new line
                item=item.split(',')
                ruleString=item[1]

                if item[0]=='ip_address':
                    key="$ip"+str(stringCounter)
                elif item[0]=='url':
                    ruleString=ruleString.replace("http://","")
                    ruleString = ruleString.replace("https://", "")
                    ruleString = ruleString.replace("/", "")
                    removePortList=ruleString.split(":")
                    ruleString = removePortList[0]
                    key="$url"+str(stringCounter)
                else:
                    key="$unknown"+str(stringCounter)

                writeLine="\t\t\t" + key + "=" + '"'+ ruleString+'"' + "\n"
                fileWriter.write(writeLine)
                stringCounter+=1
        fileWriter.write("\tcondition:\n")
        fileWriter.write("\t\t\t any of them\n")
        fileWriter.write("}\n")
    else:
        print ("ERROR: Input file not found")
