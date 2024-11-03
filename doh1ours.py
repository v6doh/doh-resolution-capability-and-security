import requests
import base64
from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.dns import DNSQR
from scapy.layers.dns import dns_get_str
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



k_path='/home/ubuntu/tlsgo/aa_1.txt'
def check_doh(ips):
    ip=ips.strip("\n")
    data = {"ip": ip, "flag1": False,"flag2":False}
    #DoH服务器
    url="https://[{}]/dns-query".format(ip)     # DoH服务器所在url
    dns_name="example.com"               # 请求域名
 

    headers={
        'accept':'application/dns-message',
        'content-type':'application/dns-message',
        'Connection':'close',
        "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36 Edg/103.0.1264.49',
    }
    # 生成DNS查询数据包
    p=DNS(id=0,qr=0,opcode=0,rd=1,qd=DNSQR(qname=dns_name,qtype=1,qclass=1))
    try:
        # get方法
        # 需要用base64url编码数据包作为参数
        param=str(base64.urlsafe_b64encode(raw(p)),encoding='utf-8')
        param=param.replace('=','')
        with httpx.Client(http2=False,verify=False,headers=headers,timeout=5) as client:
            response = client.get(url+'?dns='+param)
        if response.status_code == 200 and response.headers.get('Content-Type') == 'application/dns-message':
            data["flag1"] = True
         
        # post方法
        # 直接将数据包作为参数
        with httpx.Client(http2=False,verify=False,headers=headers,timeout=5) as client:
            response=client.post(url,data=raw(p))
        if response.status_code == 200 and response.headers.get('Content-Type') == 'application/dns-message':
            data["flag2"] = True
           
        with open(k_path, 'a') as f:
            if data["flag1"] == True or data["flag2"] == True:
                f.write(data['ip'] + ',' + str(data['flag1']) + ',' + str(data['flag2']) + '\n')
        return data
    # except requests.exceptions.ConnectionError:     
    #     return data
    # except struct.error:
    #     return data
    except Exception as ex:
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

   