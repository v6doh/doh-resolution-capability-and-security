
import argparse
import json
import sys
import time
import requests

def extract_as_number(json_line):
    try:
        data = json.loads(json_line)
        as_number = data.get('as', '').split(' ')[0]
        return as_number.replace('AS', '')  # 移除 "AS" 前缀
    except json.JSONDecodeError:
        return None

def main(args):
    parser = argparse.ArgumentParser(description="Running a series of queries on a list of AS numbers")
    parser.add_argument('input', help="Input file containing a list of JSON data with AS numbers")
    parser.add_argument('output', help="Output file to write results to")
    args = parser.parse_args(args)
    start = time.time()
    
    with open(args.input) as f_in, open(args.output, 'w') as out_file:
        raw=f_in.readlines()
        for line in raw:
            as_number = extract_as_number(line)
            if as_number:
                url = f"https://www.peeringdb.com/api/net?asn={as_number}"
                try:
                    time.sleep(15)
                    res= requests.get(url)
                    data=res.json()
                    out_file.write(json.dumps(data) + "\n")
                    print(f"AS 号: {as_number}, {data}")
                except Exception as e:
                    print(as_number, "发生错误:", str(e))
                    raw.append(line)
                    time.sleep(30)
    
    print("耗时", time.time() - start)

if __name__ == "__main__":
    main(sys.argv[1:])

