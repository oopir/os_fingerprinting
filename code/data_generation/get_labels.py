import nmap
import pickle
import os
import sys


def main():
    src_dir, dst_dir = sys.argv[1].replace('\\', '/'), sys.argv[2]
    start, end = int(sys.argv[3]), int(sys.argv[4])

    for file in sorted(os.listdir(src_dir))[start:end]:
        print('running nmap on ips from %s...' % file)
        
        nmap_cmd = '-iL %s/%s -n -p 80,443 -O --osscan-guess --min-hostgroup 100' % (src_dir, file)

        scan_res = nmap.PortScanner().scan(arguments=nmap_cmd)
        
        os_info  = {addr:info['osmatch'][:3]   for addr,info in scan_res['scan'].items()   if len(info['osmatch']) != 0}    

        dst_filename = '%s/%s%s' % (dst_dir, file, '.pkl')
        with open(dst_filename, 'wb') as curr_dst_file:
            pickle.dump(os_info, curr_dst_file) 

if __name__ == "__main__":
    main()