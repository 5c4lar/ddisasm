import json
import csv

import argparse

parser = argparse.ArgumentParser(description='Process function prototype obtained from llvm-dwarfdump')
parser.add_argument('--input', type=str,
                    help='Input file in json format.')
parser.add_argument('--output', type=str,
                    help='Output file in csv format.')

args = parser.parse_args()

def transform(type):
    if type == "DW_TAG_pointer_type":
        return "ptr"
    elif type != "DW_TAG_unspecified_parameters":
        return "data"

def main(args):
    with open(args.input, "r") as f:
        d = json.load(f)
    data = [[i['function_name'], 0, transform(i['tag'])] for i in d]
    data += [[i['function_name'], j['idx'], transform(j['tag'])] for i in d for j in i['parameters'] if j['tag'] != "DW_TAG_unspecified_parameters"]
    with open(args.output, "w") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerows(data)

if __name__ == "__main__":
    args = parser.parse_args()
    main(args)