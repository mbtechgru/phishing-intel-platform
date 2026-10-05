from fastapi import FastAPI, UploadFile, File, HTTPException, Body
from fastapi.responses import HTMLResponse, PlainTextResponse
from pathlib import Path
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse
import hashlib, re, json, uuid, datetime, ipaddress, os, socket, urllib.request, urllib.parse

ROOT=Path(__file__).resolve().parents[2]; CASES=ROOT/'cases'; CASES.mkdir(exist_ok=True)
app=FastAPI(title='PhishScope', version='0.2.0', description='Defensive phishing investigation and passive threat-intelligence platform')
URL_RE=re.compile(r"https?://[^\s<>\"']+", re.I); IP_RE=re.compile(r'(?<![\\w.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\w.])')
SAFE=re.compile(r'[^A-Za-z0-9._-]+')

def sha256(b): return hashlib.sha256(b).hexdigest()
def sanitize(s): return SAFE.sub('_', Path(s or 'unnamed').name)[:160] or 'unnamed'
def public_ip(s):
    try:
        i=ipaddress.ip_address(s); return not (i.is_private or i.is_loopback or i.is_reserved or i.is_link_local or i.is_multicast)
    except: return False

def domain_of_address(v):
    a=parseaddr(v or '')[1]; return a.rsplit('@',1)[1].lower() if '@' in a else ''

def parse_eml(data: bytes, evidence_dir: Path|None=None):
    msg=BytesParser(policy=policy.default).parsebytes(data); headers={k:str(v) for k,v in msg.items()}; bodies=[]; attachments=[]
    for idx,p in enumerate(msg.walk(),1):
        payload=p.get_payload(decode=True) or b''
        if p.get_content_disposition()=='attachment' or p.get_filename():
            name=sanitize(p.get_filename() or f'attachment-{idx}.bin'); rec={'filename':name,'content_type':p.get_content_type(),'size':len(payload),'sha256':sha256(payload)}
            if evidence_dir:
                ad=evidence_dir/'attachments'; ad.mkdir(exist_ok=True); target=ad/f'{idx:02d}-{name}'; target.write_bytes(payload); rec['evidence_path']=str(target.relative_to(evidence_dir))
            attachments.append(rec)
        elif p.get_content_type() in ('text/plain','text/html'):
            try: bodies.append(payload.decode(p.get_content_charset() or 'utf-8','replace'))
            except: pass
    text='\n'.join([str(v) for v in headers.values()]+bodies)
    urls=sorted(set(x.rstrip('.,);]') for x in URL_RE.findall(text))); domains=sorted(set(urlparse(x).hostname.lower() for x in urls if urlparse(x).hostname))
    ips=sorted(set(x for x in IP_RE.findall(text) if public_ip(x))); auth=headers.get('Authentication-Results',''); flags=[]; score=0
    fd,rd=domain_of_address(headers.get('From')),domain_of_address(headers.get('Reply-To'))
    if rd and fd and rd != fd: flags.append(f'Reply-To domain differs from From ({fd} → {rd})'); score+=25
    for mech,pts in [('spf',20),('dkim',20),('dmarc',25)]:
        if f'{mech}=fail' in auth.lower(): flags.append(f'{mech.upper()} failed'); score+=pts
    if urls: flags.append(f'{len(urls)} URL(s) found'); score+=min(15,len(urls)*3)
    if attachments: flags.append(f'{len(attachments)} attachment(s) found'); score+=min(20,len(attachments)*8)
    mitre=[{'id':'T1566','name':'Phishing'}]
    if urls: mitre.append({'id':'T1566.002','name':'Spearphishing Link'})
    if attachments: mitre.append({'id':'T1566.001','name':'Spearphishing Attachment'})
    if urls or attachments: mitre.append({'id':'T1204','name':'User Execution'})
    return {'headers':headers,'urls':urls,'domains':domains,'ips':ips,'attachments':attachments,'findings':flags,'risk_score':min(100,score),'severity':('critical' if score>=80 else 'high' if score>=60 else 'medium' if score>=30 else 'low'),'mitre':mitre}

def get_case(cid):
    p=CASES/cid/'report.json'
    if not p.exists(): raise HTTPException(404,'Case not found')
    return json.loads(p.read_text())
def save_case(r): (CASES/r['case_id']/'report.json').write_text(json.dumps(r,indent=2))
def http_json(url, headers=None, timeout=8):
    req=urllib.request.Request(url,headers={'User-Agent':'PhishScope/0.2 defensive-research',**(headers or {})})
    with urllib.request.urlopen(req,timeout=timeout) as x: return json.loads(x.read().decode('utf-8','replace'))

def rdap_domain(domain):
    try:
        d=http_json('https://rdap.org/domain/'+urllib.parse.quote(domain)); return {'handle':d.get('handle'),'ldhName':d.get('ldhName'),'status':d.get('status',[]),'events':d.get('events',[])[:6],'nameservers':[n.get('ldhName') for n in d.get('nameservers',[])[:10]]}
    except Exception as e: return {'error':str(e)[:180]}
def crtsh(domain):
    try:
        rows=http_json('https://crt.sh/?q='+urllib.parse.quote('%.'+domain)+'&output=json'); names=[]
        for r in rows[:200]: names += str(r.get('name_value','')).splitlines()
        return {'names':sorted(set(x.lower() for x in names if x and '*' not in x))[:100]}
    except Exception as e: return {'error':str(e)[:180]}
def vt_domain(domain):
    key=os.getenv('VIRUSTOTAL_API_KEY');
    if not key: return {'configured':False}
    try:
        d=http_json('https://www.virustotal.com/api/v3/domains/'+urllib.parse.quote(domain),{'x-apikey':key}); a=d.get('data',{}).get('attributes',{}); return {'configured':True,'reputation':a.get('reputation'),'last_analysis_stats':a.get('last_analysis_stats',{}),'categories':a.get('categories',{})}
    except Exception as e: return {'configured':True,'error':str(e)[:180]}

def sigma_for(r):
    senders=[r.get('headers',{}).get('From','')]; doms=r.get('domains',[])
    return "title: PhishScope Case %s\nid: %s\nstatus: experimental\ndescription: Indicators generated from an authorized defensive phishing investigation\nlogsource:\n  category: email\ndetection:\n  selection:\n    sender|contains:\n%s\n    url_domain|contains:\n%s\n  condition: selection\nfalsepositives:\n  - Legitimate messages sharing infrastructure\nlevel: %s\n"%(r['case_id'],str(uuid.uuid5(uuid.NAMESPACE_DNS,r['case_id'])),''.join('      - '+json.dumps(x)+'\n' for x in senders),''.join('      - '+json.dumps(x)+'\n' for x in doms) or '      - "none"\n',r.get('severity','medium'))
def yara_for(r):
    strings=[]
    for i,d in enumerate(r.get('domains',[])[:20]): strings.append(f'    $domain{i} = "{d}" ascii nocase')
    for i,a in enumerate(r.get('attachments',[])[:20]): strings.append(f'    $hash{i} = "{a["sha256"]}" ascii')
    if not strings: strings=['    $case = "'+r['case_id']+'" ascii']
    return 'rule PhishScope_'+re.sub('[^A-Za-z0-9_]','_',r['case_id'])+' {\n  meta:\n    description = "Indicators from defensive PhishScope case"\n  strings:\n'+'\n'.join(strings)+'\n  condition:\n    any of them\n}\n'
def stix_bundle(r):
    objs=[]
    now=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    for d in r.get('domains',[]): objs.append({'type':'indicator','spec_version':'2.1','id':'indicator--'+str(uuid.uuid5(uuid.NAMESPACE_DNS,'domain:'+d)),'created':now,'modified':now,'name':'PhishScope domain indicator','pattern_type':'stix','pattern':f"[domain-name:value = '{d}']",'valid_from':now})
    for ip in r.get('ips',[]): objs.append({'type':'indicator','spec_version':'2.1','id':'indicator--'+str(uuid.uuid5(uuid.NAMESPACE_DNS,'ip:'+ip)),'created':now,'modified':now,'name':'PhishScope IP indicator','pattern_type':'stix','pattern':f"[ipv4-addr:value = '{ip}']",'valid_from':now})
    return {'type':'bundle','id':'bundle--'+str(uuid.uuid4()),'objects':objs}

@app.get('/',response_class=HTMLResponse)
def home(): return (ROOT/'frontend'/'index.html').read_text()
@app.get('/api/health')
def health(): return {'name':'PhishScope','version':'0.2.0','virustotal_configured':bool(os.getenv('VIRUSTOTAL_API_KEY'))}
@app.post('/api/analyze')
async def analyze(file:UploadFile=File(...)):
    if not (file.filename or '').lower().endswith('.eml'): raise HTTPException(400,'Upload an .eml file')
    data=await file.read()
    if len(data)>20*1024*1024: raise HTTPException(413,'File too large (20 MB max)')
    cid=datetime.datetime.now().strftime('%Y%m%d')+'-'+uuid.uuid4().hex[:8]; d=CASES/cid; d.mkdir(); (d/'original.eml').write_bytes(data)
    r=parse_eml(data,d); r.update({'case_id':cid,'filename':sanitize(file.filename),'file_sha256':sha256(data),'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'new','notes':[],'enrichment':{}}); save_case(r); return r
@app.get('/api/cases')
def cases():
    out=[]
    for f in sorted(CASES.glob('*/report.json'),reverse=True):
        try:
            r=json.loads(f.read_text()); out.append({k:r.get(k) for k in ('case_id','filename','created_utc','risk_score','severity','status')})
        except: pass
    return out
@app.get('/api/cases/{case_id}')
def case(case_id:str): return get_case(case_id)
@app.post('/api/cases/{case_id}/enrich')
def enrich(case_id:str):
    r=get_case(case_id); enrichment={}
    for d in r.get('domains',[])[:10]: enrichment[d]={'rdap':rdap_domain(d),'certificates':crtsh(d),'virustotal':vt_domain(d)}
    r['enrichment']=enrichment; r['enriched_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat(); save_case(r); return enrichment
@app.post('/api/cases/{case_id}/notes')
def note(case_id:str,payload:dict=Body(...)):
    r=get_case(case_id); txt=str(payload.get('text','')).strip()
    if not txt: raise HTTPException(400,'Note cannot be empty')
    r.setdefault('notes',[]).append({'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'text':txt[:4000]}); save_case(r); return r['notes']
@app.post('/api/cases/{case_id}/status')
def status(case_id:str,payload:dict=Body(...)):
    r=get_case(case_id); s=str(payload.get('status','')).lower()
    if s not in ('new','investigating','contained','closed'): raise HTTPException(400,'Invalid status')
    r['status']=s; save_case(r); return {'status':s}
@app.get('/api/cases/{case_id}/sigma',response_class=PlainTextResponse)
def sigma(case_id:str): return sigma_for(get_case(case_id))
@app.get('/api/cases/{case_id}/yara',response_class=PlainTextResponse)
def yara(case_id:str): return yara_for(get_case(case_id))
@app.get('/api/cases/{case_id}/stix')
def stix(case_id:str): return stix_bundle(get_case(case_id))
