#! /usr/bin/python3

import sys, os, os.path, re, random, glob
import StringIO
import Steganography

import gnupg
from time import time, sleep
from TariqUtils import readconf, get_fingerprint, dec


import sys
sys.path.append('/usr/lib/python2.6')
sys.path.append('/usr/lib/pymodules/python2.6')
sys.path.append('/usr/local/lib/python2.6/dist-packages')
import scapy

#from scapy.all import *

bigS=re.compile(r'^\S+$')
cmd_re=re.compile(r'^([CEO]) ') # close port, execute command, open port

def gen_payload(img_fn, s):
  """
  put text s into image file img_fn x
  and return the modified image file content
  """
  in_file=StringIO.StringIO(s)
  out_file=StringIO.StringIO()
  # for example in 16-bit they use 565 for rgb see http://en.wikipedia.org/wiki/Color_depth
  # because human eye is more sensitive to the color green
  Steganography.encode(img_fn, in_file, red_bits=1, green_bits=1, blue_bits=1).save(out_file,format='png')
  return out_file.getvalue()

def split_msg(n, msg):
  l=len(msg)
  r=l//n
  msgs=[]
  j=0
  for i in range(n-1): msgs.append(msg[j:j+r]); j+=r
  msgs.append(msg[j:])
  return msgs

def knock(gpg, ports, email, img_fn, ip, cmd):
    """
    email need not be a real email, it's just a unique id within the system
    """
    if not bigS.match(email): raise KeyError
    fingerprint=get_fingerprint(gpg, email=email) # just to make sure it exists
    if not cmd_re.match(cmd): return -1
    s=email+" "+cmd
    msg=gen_payload(img_fn, s)
    l=len(msg)
    print (l)
    # open('delme2.png','wb+').write(msg)
    n=len(ports)
    msgs=split_msg(n, msg)
    t=1.0/n
    sp=RandShort()
    # knock all but last ports
    for i,p in enumerate(ports[:-1]):
        pk=IP(dst=ip)/TCP(flags='S', sport=sp, dport=p)/msgs[i]
        send(pk)
        sleep(t)
    # knock last port and wait response
    i,p=-1,ports[-1]
    pk=IP(dst=ip)/TCP(flags='S', sport=sp, dport=p)/msgs[i]
    r,u=sr(pk,timeout=0.5)
    if len(r)==0: print ("** Error: no response")
    print (r.__repr__())
    for pk in r[0]:
        print ("Got answer:",)
        if pk.payload.flags!=18: print ("skipped"); continue
        print ("OK")
        enc_blob=str(pk.payload.payload)
        # print "payload: [%s]" % enc_blob
        print ("** SENDING REST:",)
        dec_blob=dec(gpg, enc_blob)
        rpk=IP(dst=pk.src,src=pk.dst)/TCP(flags='R',dport=pk.sport, sport=pk.dport, seq=pk.seq+1)/dec_blob
        send(rpk)
    return 0
from getopt import getopt, GetoptError

def usage():
    print ('''\
Usage: {0} [-c CONF] [-p PORTS] [-i IMG_DIR] [-g GPGDIR] [-u USERID] TARGET COMMAND
\tWhere:
\t\t-c CONF
\t\t\t* specify config file
\t\t-p PORTS
\t\t\t* comma delimited no space ports to knock
\t\t-u USERID
\t\t\t* the email portion of your private GPG key


\tCOMMAD: one of the following
\t\tO PORT
\t\t\t* opens specified port for you
\t\tC PORT
\t\t\t* closes specified port
\t\tE CMD
\t\t\t* run specified command on server as root
''').format(os.path.basename(sys.argv[0]))

def main():
    random.seed(time())
    args_to_c={
      '-p':'secret_ports', '-i':'img_dir',
      '-g': 'client_gpg_dir', '-u':'user'
    }
    try:
        opts, args = getopt(sys.argv[1:], "c:p:i:g:u:", ["help"])
    except (GetoptError, err):
        print (str(err)) # will print something like "option -a not recognized"
        usage()
        sys.exit(1)
    opts=dict([(args_to_c.get(i,i),j) for i,j in opts])
    if opts.has_key('help'):
        usage()
        sys.exit(2)
    fn=opts.get('-c',None)
    if not fn:
      fn='/etc/tariq/client.conf'
    elif fn and not os.path.exists(fn):
        fn='/etc/tariq/client.conf'

    if not os.path.exists(fn):
        fn=os.path.join(os.path.dirname(sys.argv[0]),'client.conf')
    if not os.path.exists(fn):
        fn=os.path.abspath('client.conf')
    if not os.path.exists(fn):
        print (" ** Error: config file not found")
        usage()
        exit(3)
    c=readconf(fn)
    c.update(opts)
    if not all(map(lambda i: i in c,['secret_ports','img_dir', 'client_gpg_dir', 'user'])):
        print (" ** Error: missing required parameters")
        usage()
        exit(4)
    
    
    tariqPorts=map(lambda i: int(i) ,c['secret_ports'].split(','))
    user=c['user']
    img_dir=c['img_dir']
    if not os.path.isdir(img_dir):
      print (" ** Error [%s] not found") % img_dir
      usage()
      exit(5)

    img_ls=glob.glob(os.path.join(img_dir,'*.png'))
    if not img_ls:
      print (" ** Error: no png images found on [%s]") % img_dir
      usage()
      exit(5)
    img=random.choice(img_ls)
    gpg_dir=c['client_gpg_dir']
    if not os.path.isdir(gpg_dir):
      print (" ** Error [%s] not found") % gpg_dir
      print (" ** trying client_gpg_dir=[%s]") % gpg_dir
      gpg_dir=os.path.join(os.path.dirname(sys.argv[0]),'client-gpg')
    if not os.path.isdir(gpg_dir):
        print (" gpg dir not found")
        usage()
        exit(5)
    gpg = gnupg.GPG(gnupghome=gpg_dir)
    if len(args)<3:
        print (" ** missing TARGET CMD ARGS")
        usage()
        exit(6)
    target=args[0]
    cmd=" ".join(args[1:])
    knock(gpg, tariqPorts, user, img , target, cmd)

if __name__=='__main__':
    main()


