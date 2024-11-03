import base64
import httpx
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
import multiprocessing as mp
from tqdm import tqdm
import argparse
import sys
import csv
DNS_TYPES = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    12: 'PTR',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA',
    33: 'SRV',
    41: 'OPT',   # OPT记录用于EDNS
    24: 'SIG',   # SIG记录用于DNSSEC

}
def extract_dns_record(record):
    if not record:
        return "None"
    entries = []
    while record:
        if record.rrname:  # Ensure we are dealing with a DNS resource record
            entry = [
                record.rrname.decode('utf-8') if isinstance(record.rrname, bytes) else record.rrname,
                DNS_TYPES.get(record.type, "Unknown"),
                record.rdata.decode('utf-8') if isinstance(record.rdata, bytes) else str(record.rdata)
            ]
            entry_info = "; ".join(str(e) for e in entry)
            entries.append(entry_info)
            record = record.payload
        else:
            break
    return "; ".join(entries)

def parse_dns_packet(packet):
    dns = DNS(packet)
    ans = extract_dns_record(dns.an)
    auth = extract_dns_record(dns.ns)
    add = extract_dns_record(dns.ar)
    return ans, auth, add

def check_doh(ip):
    ip = ip.strip("\n")
    data = {"ip": ip, "flag1": False, "flag2": False, "get_ans": "None", "get_auth": "None", "get_add": "None", "post_ans": "None", "post_auth": "None", "post_add": "None"}
    url = f"https://[{ip}]/dns-query"
    headers = {
        'Accept': 'application/dns-message',
        'Content-Type': 'application/dns-message',
        'Connection': 'close',
        "User-Agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36 Edg/103.0.1264.49',
    }
    query = DNS(id=0, qr=0, opcode=0, rd=1, qd=DNSQR(qname="example.com", qtype=1, qclass=1))
    query_encoded = str(base64.urlsafe_b64encode(raw(query)), encoding='utf-8').replace('=', '')
    
    try:
        with httpx.Client(http2=True, verify=False, headers=headers, timeout=10) as client:
            response = client.get(f"{url}?dns={query_encoded}")
        if response.http_version!="HTTP/2":
            return data
        if response.status_code == 200 and response.headers.get('Content-Type') == 'application/dns-message':
            ans, auth, add = parse_dns_packet(response.content)
            data["get_ans"] = ans
            data["get_auth"] = auth
            data["get_add"] = add
            data["flag1"] = True

        with httpx.Client(http2=True, verify=False, headers=headers, timeout=10) as client:
            response = client.post(url, data=raw(query))
        if response.http_version!="HTTP/2":
            return data
        if response.status_code == 200 and response.headers.get('Content-Type') == 'application/dns-message':
            ans, auth, add = parse_dns_packet(response.content)
            data["post_ans"] = ans
            data["post_auth"] = auth
            data["post_add"] = add
            data["flag2"] = True
    except Exception as e:
        print(f"Error checking {ip}: {e}")
    
    return data

def main(args):
    parser = argparse.ArgumentParser(description="Run a series of DNS queries on a list of IPs")
    parser.add_argument('input', help="Input file containing a list of IPs")
    parser.add_argument('output', help="Output directory to write results to")
    parser.add_argument('-n', '--num-threads', default=64, type=int)
    args = parser.parse_args(args)
    
    targets = open(args.input).readlines()

    output_csv_path = args.output + "dns_query_results.csv"
    with open(output_csv_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['IP', 'GET Full Record', 'POST Full Record'])
        with mp.Pool(processes=args.num_threads) as pool:
            results = list(tqdm(pool.imap(check_doh, targets), total=len(targets)))
            for result in results:
                if result['flag1'] or result['flag2']:  # Only write if there was a successful HTTP/2 response
                    writer.writerow([result['ip'], result['get_ans'] + '; ' + result['get_auth'] + '; ' + result['get_add'], result['post_ans'] + '; ' + result['post_auth'] + '; ' + result['post_add']])

if __name__ == "__main__":
    main(sys.argv[1:])