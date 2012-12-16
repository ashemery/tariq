#! /usr/bin/python3
import sys, time, hashlib, random

import StringIO
import Steganography

import gnupg

from Queue import Queue
from threading import Thread
from subprocess import Popen, PIPE

from TariqUtils import readconf, get_fingerprint, enc


import sys
sys.path.append('/usr/lib/python2.6')
sys.path.append('/usr/lib/pymodules/python2.6')
sys.path.append('/usr/local/lib/python2.6/dist-packages')
import scapy

#from scapy.all import *


cmd_re=re.compile(r'^([CEO]) ') # close port, execute command, open port

def randomblob(m,M):
  return (''.join(map(lambda i: chr(random.randrange(0,255)), range(random.randrange(m,M))))).encode('base64')

class TariqServer(AnsweringMachine):
    function_name = "TariqServer"
    filter = "tcp and dst portrange 1000-65535"
    send_function = staticmethod(send)
    def __init__(self, fn, *args, **kw):
        random.seed(time.time())
        self._ps=[]
        self._setsid = getattr(os, 'setsid', None)
        if not self._setsid: self._setsid = getattr(os, 'setpgrp', None)
        self._q = Queue(0)
        self._process_conf(fn)
        self._start_threads()
        self._portsN=len(self._ports)
        self._hist={}
        self._challenge={}
        self._gpg = gnupg.GPG(gnupghome=self._server_gpg_dir)
        AnsweringMachine.__init__(self, *args, **kw)

    def _get_iptables_rule_n(self, ip, dport):
        """
        returns rule number or 0 if not found
        """
        p=Popen(self._iptables_dump_cmd, 0, '/bin/bash',shell=True, stdout=PIPE)
        l=p.communicate()[0].strip().splitlines()
        if not l or not l[0].startswith('-N'): return 0
        for i,j in enumerate(l):
            #print "matching with rule %d which is [%s]" % (i,j)
            m=self._open_tcp_port_re.match(j)
            if m and m.group('ip')==ip and int(m.group('dport'))==dport:
                return i
            m=self._open_udp_port_re.match(j)
            if m and m.group('ip')==ip and int(m.group('dport'))==dport:
                return i
        return 0

    def _run_shell_cmd(self, cmd):
        self._ps=filter(lambda x: x.poll()!=None,self._ps) # remove terminated processes from _ps list
        self._ps.append(Popen(cmd,0,'/bin/bash',shell=True, preexec_fn=self._setsid))

    def _run_cmd(self, ip, cmd, args):
      if cmd=="E":
          print (' ** running [%s]') % args
          self._run_shell_cmd(args)
      elif cmd=='C':
          if not args.isdigit():
              print (" ** Error: dport should be an integer")
              return
          k=1
          while(k):
              k=self._get_iptables_rule_n(ip, int(args))
              if k: self._run_shell_cmd('/sbin/iptables -D %s %d' % (self._iptables_chain, k))
      elif cmd=='O':
          if not args.isdigit():
              print (" ** Error: dport should be an integer")
              return
          self._run_shell_cmd('/sbin/iptables '+self._open_tcp_port.format(ip=ip, dport=args))
          self._run_shell_cmd('/sbin/iptables '+self._open_udp_port.format(ip=ip, dport=args))
      else:
          print (" ** Error: cmd=[%s] not supported") % cmd

    def _worker(self):
        while self._keepworking:
            self._started=True
            # get a job from queue or block sleeping till one is available
            item = self._q.get(not self._end_when_done)
            if item:
                ip,cmd,args=item
                self._run_cmd(ip, cmd, args)
                self._q.task_done()
            elif self._q.empty() and self._end_when_done:
                self._keepworking=False

    def _start_threads(self):
        self._keepworking=True
        self._end_when_done=False
        self._started=False
        # here we create our thread pool of workers
        for i in range(self._threads_n):
          t = Thread(target=self._worker)
          t.setDaemon(True)
          t.start()
        # sleep to make sure all threads are waiting for jobs (inside loop)
        while not self._started: time.sleep(0.25)

    def _process_conf(self, fn):
        c=readconf(fn)
        print ("config=", c)
        self._server_gpg_dir=c['server_gpg_dir']
        if not os.path.isabs(self._server_gpg_dir):
            self._server_gpg_dir=os.path.join(os.path.dirname(sys.argv[0]),self._server_gpg_dir)
        self._server_gpg_dir=os.path.expanduser(self._server_gpg_dir)
        self._ports=[int(i.strip()) for i in c['secret_ports'].split(',')]
        self.filter="tcp and dst portrange %s" % c['sniff_range'].strip()
        self._threads_n=int(c['threads_n'].strip())
        self._open_tcp_port=c['open_tcp_port'].strip()
        self._open_udp_port=c['open_udp_port'].strip()
        self._open_tcp_port_re=re.compile(re.escape(self._open_tcp_port).replace('\\{','{').replace('\\}','}').format(ip=r'(?P<ip>[\d.]+)(?:/\S*)?', dport=r'(?P<dport>\d+)'))
        self._open_udp_port_re=re.compile(re.escape(self._open_udp_port).replace('\\{','{').replace('\\}','}').format(ip=r'(?P<ip>[\d.]+)(?:/\S*)?', dport=r'(?P<dport>\d+)'))
        self._iptables_chain=c['iptables_chain']
        self._iptables_dump_cmd='/sbin/iptables -S '+self._iptables_chain
        if c['just_check_sequence'].strip()=='1':
            self._filter_more()
        self._blobm=int(c['min_random_blob_size'].strip())
        self._blobM=int(c['max_random_blob_size'].strip())

    def _filter_more(self):
        """
        filter only needed ports to sniff
        """
        c=" or ".join("dst port %d" % p for p in self._ports)
        self.filter = "tcp and ( %s )" % c
    
    def send_reply(self, reply):
        if reply!=None: self.send_function(reply, **self.optsend)

    def print_reply(self, req, reply):
        if req and reply: AnsweringMachine.print_reply(self, req, reply)

    def is_request(self, req):
        return 1

    def _is_right_knock(self, s, dp):
        if s in self._hist:
            n=len(self._hist[s])
            # if it's the same as last one, ignore it
            if n>1 and n<self._portsN and self._ports[n-1]==dp:
              print ("** duplicated port ignored")
              return False
            # make sure it's in right sequence
            if n<self._portsN and self._ports[n]==dp: return True
            elif self._ports[0]==dp:
                self._hist[s]=[]
                return True
            del self._hist[s]
        elif dp==self._ports[0]:
            self._hist[s]=[]
            return True
        return False

    def make_reply(self, req):
        pk=IP(str(req.payload))
        tcp=pk.payload
        if tcp.flags!=4 and tcp.flags!=2: return None
        d=str(tcp.payload)
        dp=int(tcp.dport)
        s=str(pk.src)
        if tcp.flags==4:
            if dp!=self._ports[-1] or not self._challenge.has_key(s): return None
            if d.replace('\0',' ').strip()=='': return None
            print ("** Got challenge answer=[%s]") % d.__repr__()
            c,cmd,arg=self._challenge[s]
            if c==d:
                print ("** accepted, executing cmd=[%s] arg=[%s]") % (cmd,arg)
                self._q.put((s, cmd, arg))
            else: print ("rejected")
            del self._challenge[s]
            return None
        print ("dp=",dp,)
        #print "pk=", pk.__repr__()
        r=self._is_right_knock(s, dp)
        print ("** right order=", r)
        if not r: return None
        self._hist[s].append(d)
        if len(self._hist[s])==self._portsN:
            # send challenge
            img="".join(self._hist[s])
            del self._hist[s];
            in_file=StringIO.StringIO(img)
            try: d=Steganography.decode(in_file, red_bits=1, green_bits=1, blue_bits=1)
            except: return None
            try: email,cmd,arg=d.split(' ',2)
            except ValueError: return None
            print ("** last valid knock received, cmd=[%s] arg=[%s]") % (cmd, arg)
            print ("** sending challenge ...")
            dec_blob=randomblob(self._blobm,self._blobM)
            enc_blob=enc(self._gpg, dec_blob, email=email)
            print ("** expecting answer=[%s]") % dec_blob.__repr__()
            try: self._challenge[s]=(dec_blob, cmd, arg)
            except KeyError: return None
            return IP(dst=pk.src,src=pk.dst)/TCP(flags='SA',dport=tcp.sport, sport=tcp.dport, seq=tcp.seq)/enc_blob
        return None

def main():
    if len(sys.argv)==2 and os.path.exists(sys.argv[1]): fn=sys.argv[1]
    else: fn='/etc/tariq/server.conf'

    if not os.path.exists(fn):
        fn=os.path.join(os.path.dirname(sys.argv[0]),'server.conf')
    if not os.path.exists(fn):
        fn=os.path.abspath('server.conf')
    if not os.path.exists(fn):
        print (" ** Error: config file not found")
        exit(1)
    server=TariqServer(fn)
    server()

if __name__=='__main__':
    main()

