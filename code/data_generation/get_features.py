import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from scapy.layers.inet import IP,TCP
from random import randint
import pickle
from concurrent.futures import ThreadPoolExecutor
import requests


def get_tcp_opt(p, opt, default):
    if opt in map(lambda tup : tup[0], p['TCP'].options):
        return reduce(lambda opt1,opt2 : opt1 if opt1[0]==opt else opt2, p['TCP'].options)[1]
    return default


def send_http_req(ip):
    try:
        tmp = requests.get(f'https://{ip}', timeout=10)
    except Exception as e:
        pass


def main():
    src_dir, dst_dir = sys.argv[1].replace('\\', '/'), sys.argv[2]
    start, end = int(sys.argv[3]), int(sys.argv[4])

    for filename in sorted(os.listdir(src_dir))[start:end]:
        ips, features = [], {}
        print(f'working on {filename}...')

        # open current file
        print(f'\treading ips...')
        with open('%s\\%s' % (src_dir, filename), 'rt') as curr_input_file:
            ips = list(map(lambda line : line.rstrip('\n'), curr_input_file))

        # start sniffing
        print(f'\tstarting capture...')
        sniffer = AsyncSniffer(filter='src port 443 and tcp[tcpflags] & (tcp-syn|tcp-ack|tcp-push) == (tcp-syn|tcp-ack)')
        sniffer.start()
        
        # send http requests to all ips of current file
        print(f'\trunning threads...')
        if sys.argv[-1] != 'debug':
            with ThreadPoolExecutor(max_workers = 100) as executor:
                executor.map(send_http_req, ips)
        else:
            for ip in ips:
                print(f'\t\tworking on {ip}...')
                send_http_req(ip)

        print(f'\tstopping capture...')
        res = sniffer.stop()

        print(f'\textracting features from {len(res)} addresses...')
        # gathering features from syn_ack packets
        for SA in res:
            curr_data = {
                'df'      : 1 if 'DF' in str(SA['IP'].flags) else 0 ,
                'ttl'     : SA['IP'].ttl ,
                'w_size'  : SA['TCP'].window ,
                'mss'     : get_tcp_opt(SA, 'MSS', default=-1) ,
                'w_scale' : get_tcp_opt(SA, 'WScale', default=1) ,

                'df+'  : 1  if (    'DF' in str(SA['IP'].flags) and not SA['IP'].id)    else 0 ,
                'df-'  : 1  if (not 'DF' in str(SA['IP'].flags) and     SA['IP'].id)    else 0 ,
                'fo+'  : 1  if (not 'DF' in str(SA['IP'].flags) and     SA['IP'].frag)  else 0 ,
                'fo-'  : 1  if (    'DF' in str(SA['IP'].flags) and not SA['IP'].frag)  else 0 ,

                'ecn'  : 1  if ('E' in SA['TCP'].flags)                                else 0 ,
                'seq0' : 1  if (SA['TCP'].seq == 0)                                    else 0 ,

                'opts' : ','.join([str(opt[0]) for opt in SA['TCP'].options])
            }
            features[SA['IP'].src] = curr_data

        # save features to file
        print(f'\tsave features...')
        dst_filename = '%s/%s%s' % (dst_dir, filename, '.pkl')
        with open(dst_filename, 'wb') as curr_dst_file:
            pickle.dump(features, curr_dst_file) 



if __name__ == "__main__":
    main()