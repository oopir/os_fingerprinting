import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.inet import IP,TCP
from random import randint
import pickle
from concurrent.futures import ThreadPoolExecutor


# -------------------------------------- GLOBALS --------------------------------------
opt_to_num = {opt:i  for i,opt  in enumerate(scapy.layers.inet.TCPOptions[1].keys())}
opt_to_num["NONE"] = -1
opts_set = set()
# -------------------------------------------------------------------------------------


def get_tcp_opt(p, opt, default):
    if opt in map(lambda tup : tup[0], p['TCP'].options):
        return reduce(lambda opt1,opt2 : opt1 if opt1[0]==opt else opt2, p['TCP'].options)[1]
    return default


def get_features_of(addr):
    global opts_set

    # attempt to get SYN_ACK packet from server
    syn = IP(dst=addr)/TCP(dport=443, flags='S', seq=randint(0,2**32))
    rst = IP(dst=addr)/TCP(dport=443, flags='R')
    SA  = sr1(syn, retry=5, timeout=3, verbose=0)
    tmp = send(rst, verbose=0)
    
    if SA == None:
        return addr, None

    opts_set.add(''.join([o[0] for o in SA['TCP'].options]))

    # extract features from the response
    # some feature names are taken from p0f in order to have reference for their meaning
    features = {
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
        'seq0' : 1  if (SA['TCP'].seq == 0)                                    else 0
    }

    for i,opt in enumerate(SA['TCP'].options):
        if opt[0] in opt_to_num:
            features['opt%d' % (i)] = opt_to_num[opt[0]]
        else:
            features['opt%d' % (i)] = int(opt[0])
    for i in range(len(SA['TCP'].options), 10):
        features['opt%d' % (i)] = -1

    return addr, features
    

def main():
    global opts_set 

    src_dir, dst_dir = sys.argv[1].replace('\\', '/'), sys.argv[2]
    skip = int(sys.argv[3])
    for filename in sorted(os.listdir(src_dir))[skip:]:
    # for filename in sorted(os.listdir(src_dir)):
        print('collecting features for file %s...', filename)
        ips, features = [], {}

        # read ips from current file
        with open('%s\\%s' % (src_dir, filename), 'rt') as curr_input_file:
            ips = list(map(lambda line : line.rstrip('\n'), curr_input_file))
        
        # collect features
        with ThreadPoolExecutor(max_workers = 100) as executor:
            features = {addr:data  for addr, data  in executor.map(get_features_of, ips)  if data != None}

        # save features to file
        dst_filename = '%s/%s%s' % (dst_dir, filename, '.pkl')
        with open(dst_filename, 'wb') as curr_dst_file:
            pickle.dump(features, curr_dst_file) 

    print(opts_set)

if __name__ == "__main__":
    main()