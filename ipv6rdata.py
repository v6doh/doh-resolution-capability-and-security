
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
        if record.rrname or record.type == 41:  # Ensure we are dealing with a DNS resource record or OPT record
            if record.type == 41:  # Special handling for OPT records
                # rclass for OPT records represents the maximum UDP payload size
                entries.append(f"OPT UDP Payload Size={record.rclass}")
            else:
                entry = [
                    record.rrname.decode('utf-8') if isinstance(record.rrname, bytes) else record.rrname,
                    DNS_TYPES.get(record.type, "Unknown"),
                    record.rdata.decode('utf-8') if isinstance(record.rdata, bytes) else str(record.rdata),
                    f"TTL={record.ttl}, RDLEN={record.rdlen}"
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


def check_doh(ip_and_values):
    ip_and_values = ip_and_values.strip("\n").split()
    ip = ip_and_values[0]
    expected_values = {
        'getra': int(ip_and_values[1]),
        'getaa': int(ip_and_values[2]),
        'getrcode': int(ip_and_values[3]),
        'getancount': int(ip_and_values[4]),
        'getnscount': int(ip_and_values[5]),
        'getarcount': int(ip_and_values[6]),
        'postra': int(ip_and_values[7]),
        'postaa': int(ip_and_values[8]),
        'postrcode': int(ip_and_values[9]),
        'postancount': int(ip_and_values[10]),
        'postnscount': int(ip_and_values[11]),
        'postarcount': int(ip_and_values[12]),
    }

    data = {
        "ip": ip,
        "flag1": False,
        "flag2": False,
        "get_ans": "None",
        "get_auth": "None",
        "get_add": "None",
        "post_ans": "None",
        "post_auth": "None",
        "post_add": "None",
        "get_age": "None",
        "get_cache_control": "None",
        "post_age": "None",
        "post_cache_control": "None"
    }
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
            if response.http_version == "HTTP/2" and response.status_code == 200 and response.headers.get('Content-Type') == 'application/dns-message':
                age = response.headers.get('Age', 'None')
                cache_control = response.headers.get('Cache-Control', 'None')
                dns_response = DNS(response.content)
                if (dns_response.ra == expected_values['getra'] and
                    dns_response.aa == expected_values['getaa'] and
                    dns_response.rcode == expected_values['getrcode'] and
                    dns_response.ancount == expected_values['getancount'] and
                    dns_response.nscount == expected_values['getnscount'] and
                    dns_response.arcount == expected_values['getarcount']):
                    ans, auth, add = parse_dns_packet(response.content)
                    data.update({
                        "get_ans": ans,
                        "get_auth": auth,
                        "get_add": add,
                        "get_age": age,
                        "get_cache_control": cache_control,
                        "flag1": True
                    })

        with httpx.Client(http2=True, verify=False, headers=headers, timeout=10) as client:
            response = client.post(url, data=raw(query))
            if response.http_version == "HTTP/2" and response.status_code == 200 and response.headers.get('Content-Type') == 'application/dns-message':
                age = response.headers.get('Age', 'None')
                cache_control = response.headers.get('Cache-Control', 'None')
                dns_response = DNS(response.content)
                if (dns_response.ra == expected_values['postra'] and
                    dns_response.aa == expected_values['postaa'] and
                    dns_response.rcode == expected_values['postrcode'] and
                    dns_response.ancount == expected_values['postancount'] and
                    dns_response.nscount == expected_values['postnscount'] and
                    dns_response.arcount == expected_values['postarcount']):
                    ans, auth, add = parse_dns_packet(response.content)
                    data.update({
                        "post_ans": ans,
                        "post_auth": auth,
                        "post_add": add,
                        "post_age": age,
                        "post_cache_control": cache_control,
                        "flag2": True
                    })
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
        writer.writerow(['IP', 'GET_AN', 'POST_AN', 'GET_NS', 'POST_NS', 'GET_AR', 'POST_AR', 'GET_AGE_TTL', 'POST_AGE_TTL', 'GET_CACHE_CONTROL', 'POST_CACHE_CONTROL', 'FLAG1', 'FLAG2'])
        with mp.Pool(processes=args.num_threads) as pool:
            results = list(tqdm(pool.imap(check_doh, targets), total=len(targets)))
            for result in results:
                writer.writerow([
                    result['ip'], result['get_ans'], result['post_ans'], result['get_auth'], 
                    result['post_auth'], result['get_add'], result['post_add'], result['get_age'], 
                    result['post_age'], result['get_cache_control'], result['post_cache_control'], 
                    result['flag1'], result['flag2']
                ])

if __name__ == "__main__":
    main(sys.argv[1:])
