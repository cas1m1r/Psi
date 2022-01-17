import requests
import json

ban_lists = ['https://www.binarydefense.com/banlist.txt']


def load_log(logfile):
    return json.loads(open(logfile,'rb').read().decode())


def create_blocklist():
    bad_ips = []
    for blocklist in ban_lists:
        for ip in requests.get(blocklist).text.split('\n'):
            if len(ip.split('.'))>2 and ip.find('#')<0:
                bad_ips.append(ip)
    open('blocklist.txt','w').write('\n'.join(blocklist))
    return bad_ips