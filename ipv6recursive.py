'''
	本代码通过解析IPv6 DoH服务器的DoH响应中的DNS响应数据包, 获取IPv6 DoH服务器在DoH递归查询中的应用情况
	输入为ipv6格式的文件, 参数依次为-n ,进程数量, 输入文件, 输出文件前缀
	example: python ipv6recursive.py -n 50 input.txt output
	输出为三个文件, 其中recursive_path可以输出DoH GET和DoH POST方法下DNS响应数据报中的RA, AA, rcode, ANCOUNT,NSCOUNT,ARCOUNT字段值,
    have_path输出支持DoH递归的服务器, no_path输出不支持DoH递归的服务器

'''
import requests
import base64
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR, dnsqtypes, dnsclasses
import time
import subprocess
import re
import xlwt
import multiprocessing as mp
from tqdm import tqdm
import csv
import sys
import argparse
import socket
from urllib3.connection import HTTPConnection
import httpx

import warnings
warnings.filterwarnings("ignore")



recursive_path='/home/ubuntu/rdlen/recursive.txt'
def check_doh(ips):
    ip = ips.strip("\n")
    getan = getns = getar = postan = postns = postar = -1
    getra = postra = 0
    getaa=postaa=-1
    getrcode=postrcode="-1"
    data = {"ip": ip, "flag1": False, "flag2": False}

    url = f"https://[{ip}]/dns-query"  # DoH服务器所在url
    dns_name = "example.com"  # 请求域名
    headers = {
        'accept': 'application/dns-message',
        'content-type': 'application/dns-message',
        'Connection': 'close',
        "User-Agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36 Edg/103.0.1264.49',  # User-Agent
    }

    # 生成DNS查询数据包
    p = DNS(id=0, qr=0, opcode=0, rd=1, qd=DNSQR(qname=dns_name, qtype=1, qclass=1))

    try:
        # GET 方法
        param = str(base64.urlsafe_b64encode(raw(p)), encoding='utf-8').replace('=', '')
        with httpx.Client(http2=True, verify=False, headers=headers, timeout=10) as client:
            response = client.get(url + '?dns=' + param)

        if response.http_version != "HTTP/2":
            getra = -1
            get_error_info = "GET Error: HTTP/2 not supported"
        elif response.status_code == 200 and response.headers.get('Content-Type') == 'application/dns-message':
            result = response.content
            if len(result) >= 2:
                dns_packet = DNS(result)
                getaa=dns_packet.aa
                getrcode = dns_packet.rcode
                if dns_packet.ra == 1:
                    getra = 1
                    data["flag1"] = True
                    getan = dns_packet.ancount
                    getns = dns_packet.nscount
                    getar = dns_packet.arcount
                else:
                    getan = dns_packet.ancount
                    getns = dns_packet.nscount
                    getar = dns_packet.arcount
            else:

                getan = getns = getar = -2
                get_error_info = "GET Error: No DNS data in response"
        else:
            getan = getns = getar = -3
            get_error_info = f"GET Error: Status {response.status_code}, Content-Type: {response.headers.get('Content-Type')}"

        # POST 方法
        with httpx.Client(http2=True, verify=False, headers=headers, timeout=10) as client:
            response = client.post(url, data=raw(p))

        if response.http_version != "HTTP/2":
            postra = -1
            post_error_info = "POST Error: HTTP/2 not supported"
        elif response.status_code == 200 and response.headers.get('Content-Type') == 'application/dns-message':
            result = response.content
            if len(result) >= 2:
                dns_packet = DNS(result)
                postaa=dns_packet.aa
                postrcode = dns_packet.rcode 
                if dns_packet.ra == 1:
                    postra = 1
                    data["flag2"] = True
                    postan = dns_packet.ancount
                    postns = dns_packet.nscount
                    postar = dns_packet.arcount
                else:
                    postan = dns_packet.ancount
                    postns = dns_packet.nscount
                    postar = dns_packet.arcount
            else:
                postan = postns = postar = -2
                post_error_info = "POST Error: No DNS data in response"
        else:
            postan = postns = postar = -3
            post_error_info = f"POST Error: Status {response.status_code}, Content-Type: {response.headers.get('Content-Type')}"

    except Exception as ex:
        error_info = f"Exception: {str(ex)}"
        with open(recursive_path, 'a') as f:
            f.write(f"{ip} Exception: {error_info}\n")
        return data

    # 将结果和错误信息写入文件
    with open(recursive_path, 'a') as f:
        output_line = f"{ip} {getra} {getaa} {getrcode} {getan} {getns} {getar} {postra} {postaa} {postrcode} {postan} {postns} {postar}"
        if 'get_error_info' in locals():
            output_line += f" {get_error_info}"
        if 'post_error_info' in locals():
            output_line += f" {post_error_info}"
        f.write(output_line + "\n")



    return data


def main(args):
    global transport_type
    parser = argparse.ArgumentParser(description="Running a series of dns queries on a list of IPs")
    parser.add_argument('input', help="Input file containing a list of IPs")
    parser.add_argument('output', help="Output dir to write results to")
    parser.add_argument('-n', '--num-threads', help="Number of threads to execute queries", default=64, type=int)
    parser.add_argument('-p', '--position_bar',
                        help="The position of the tqdm progress bar. Used when running multiple", type=int, default=0)

    args = parser.parse_args(args)
   

    in_file = open(args.input)  # 读取输入文件
    targets = in_file.readlines()
    if not targets[0][0].isdecimal():
        targets = targets[1:]
    in_file.close()

    have_path = args.output+"dns_query_have_doh.txt"  # 定义文件名称
    no_path =args.output+"dns_query_no_doh.txt"

    threads = min(args.num_threads, len(targets))

    with open(have_path, 'w') as dns_query_have_file, open(no_path, 'w') as dns_query_no_file:
        with mp.Pool(processes=threads) as p:
            try:
                for result in tqdm(p.imap_unordered(check_doh, targets), total=len(targets),
                                   desc="{} ({} threads)".format("doh-check", threads), position=args.position_bar):
                    # 写入文件
                    if result['flag1']==True and result['flag2']==True:
                        dns_query_have_file.write(result["ip"] + "\n")
                    else:
                        dns_query_no_file.write(result["ip"] + "\n")
            except KeyboardInterrupt:
                p.terminate()
                p.join()
                print("Exiting early from queries. Current results will still be written")
if __name__ == "__main__":
    main(sys.argv[1:])

   