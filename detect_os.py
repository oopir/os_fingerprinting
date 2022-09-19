import sys
import pickle
import requests
import threading
import math
import socket
import pandas as pd

from scapy.all import *

from sklearn.compose         import make_column_transformer
from sklearn.preprocessing   import OneHotEncoder, LabelEncoder

from sklearn.ensemble        import HistGradientBoostingClassifier
from sklearn.svm             import SVC




def get_tcp_opt(p, opt, default):
    if opt in map(lambda tup : tup[0], p['TCP'].options):
        return reduce(lambda opt1,opt2 : opt1 if opt1[0]==opt else opt2, p['TCP'].options)[1]
    return default


def send_http_req(ip):
    try:
        tmp = requests.get(f'https://{ip}', timeout=10)
    except Exception as e:
        pass


def get_target_synack(ip):
    sniffer = AsyncSniffer(filter='src port 443 and tcp[tcpflags] & (tcp-syn|tcp-ack|tcp-push) == (tcp-syn|tcp-ack)')
    sniffer.start()
    
    x = threading.Thread(target=send_http_req, args=(ip,))
    x.start()
    x.join()

    res = sniffer.stop()

    SA_list = list(filter(lambda p: p['IP'].src == ip, res))
    if len(SA_list) == 0:
        print('Did not get response from server :(')
        exit(1)

    return SA_list[0]


def create_datapoint_for_target(ip, encoders):
    # get SYN_ACK packet from server
    SA = get_target_synack(ip)

    # parse data into a feature dictionary
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
    curr_data['ttl'] = 2 ** math.ceil(math.log(curr_data['ttl'], 2))
    curr_data.pop('mss')

    # convert dictionary to dataframe, then encode dataframe
    X = pd.DataFrame.from_dict([curr_data])
    X['opts'] = encoders['opts_encoder'].transform(X['opts'])
    X = encoders['column_transformer'].transform(X)

    return X


def load_models(models_dir):
    # load models from pkl file
    with open(f'{models_dir}\\svm_linear.pkl', 'rb') as f:
        svm_linear = pickle.load(f)
    with open(f'{models_dir}\\svm_rbf.pkl', 'rb') as f:
        svm_rbf    = pickle.load(f)
    with open(f'{models_dir}\\svm_poly.pkl', 'rb') as f:
        svm_poly   = pickle.load(f)
    with open(f'{models_dir}\\hgb.pkl', 'rb') as f:
        hgb        = pickle.load(f)

    return svm_linear, svm_rbf, svm_poly, hgb
    



def main():
    # fetch ip, resolve hostname if needed
    ip = sys.argv[1]
    try:
        socket.inet_aton(ip)
    except socket.error:
        ip = socket.gethostbyname(sys.argv[1])
        print(ip)

    # import encoders
    with open('data\\models\\encoders.pkl', 'rb') as f :
        encoders = pickle.load(f)

    # get features for the given IP
    target_data = create_datapoint_for_target(ip, encoders)

    # load models
    # TODO: load neural network model
    svm_linear, svm_rbf, svm_poly, hgb = load_models('data\\models')

    # apply models
    for classifier in [svm_linear, svm_rbf, svm_poly]:
        print(encoders['label_encoder'].inverse_transform(classifier.predict(target_data)))

    print(encoders['label_encoder'].inverse_transform(hgb.predict(target_data.toarray())))
    



if __name__ == "__main__":
    main()