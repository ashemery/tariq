import gnupg

def readconf(fn, d={}):
  h=d.copy()
  A=open(fn,"rt+").readlines()
  for l in A:
    l=l.strip()
    if not l or l.startswith('#'): continue
    a=l.split('=',1)
    if len(a)!=2: continue
    h[a[0]]=a[1]
  return h

def get_fingerprint(gpg, email=None, keyid=None, fingerprint=None):
  if email==None and keyid==None and fingerprint==None: raise KeyError
  if fingerprint!=None:
    # this redundant check is to make sure that finger print is in keyring
    keys=filter(lambda k: k['fingerprint']==keyid,gpg.list_keys())
  elif keyid!=None:
    keys=filter(lambda k: k['keyid']==keyid,gpg.list_keys())
  else:
    e="<"+email+">"
    keys=filter(
      lambda k: any(map(lambda u: u.endswith(e) ,k['uids'])),
      gpg.list_keys()
    )
  if not keys: raise KeyError
  key=keys[0]
  fingerprint=key['fingerprint']
  return fingerprint

def enc(gpg, s, **kw):
  """
  enc payload s using email or keyid or fingerprint
  """
  fingerprint=get_fingerprint(gpg,**kw)
  return gpg.encrypt(s, fingerprint).data

def dec(gpg, s, **kw):
  """
  enc payload s using email or keyid or fingerprint
  """
  return gpg.decrypt(s).data
