from fastapi import FastAPI, UploadFile, File, HTTPException, Body
from fastapi.responses import HTMLResponse, PlainTextResponse
from pathlib import Path
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse
from collections import Counter
import hashlib, re, json, uuid, datetime, ipaddress, os, socket, urllib.request, urllib.parse, html

ROOT=Path(__file__).resolve().parents[2]; CASES=ROOT/'cases'; CASES.mkdir(exist_ok=True)
VERSION='0.3.0'
app=FastAPI(title='PhishScope', version=VERSION, description='Defensive phishing investigation, IOC correlation and passive threat-intelligence platform')
URL_RE=re.compile(r"https?://[^\s<>\"']+", re.I); IP_RE=re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
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
    if fd: domains=sorted(set(domains+[fd]))
    def flag(text,pts):
        nonlocal score
        flags.append(text); signals.append({'text':text,'points':pts}); score+=pts
    signals=[]
    if rd and fd and rd != fd: flag(f'Reply-To domain differs from From ({fd} → {rd})',25)
    for mech,pts in [('spf',20),('dkim',20),('dmarc',25)]:
        if f'{mech}=fail' in auth.lower(): flag(f'{mech.upper()} failed',pts)
    if urls: flag(f'{len(urls)} URL(s) found',min(15,len(urls)*3))
    if attachments: flag(f'{len(attachments)} attachment(s) found',min(20,len(attachments)*8))
    mitre=[{'id':'T1566','name':'Phishing'}]
    if urls: mitre.append({'id':'T1566.002','name':'Spearphishing Link'})
    if attachments: mitre.append({'id':'T1566.001','name':'Spearphishing Attachment'})
    if urls or attachments: mitre.append({'id':'T1204','name':'User Execution'})
    return {'headers':headers,'urls':urls,'domains':domains,'ips':ips,'attachments':attachments,'findings':flags,'signals':signals,'raw_score':score,'risk_score':min(100,score),'severity':('critical' if score>=80 else 'high' if score>=60 else 'medium' if score>=30 else 'low'),'mitre':mitre}

def get_case(cid):
    p=CASES/cid/'report.json'
    if not p.exists(): raise HTTPException(404,'Case not found')
    return json.loads(p.read_text())
def save_case(r): (CASES/r['case_id']/'report.json').write_text(json.dumps(r,indent=2))
def all_cases():
    out=[]
    for f in sorted(CASES.glob('*/report.json'),reverse=True):
        try: out.append(json.loads(f.read_text()))
        except: pass
    return out
def http_json(url, headers=None, timeout=8):
    req=urllib.request.Request(url,headers={'User-Agent':'PhishScope/'+VERSION+' defensive-research',**(headers or {})})
    with urllib.request.urlopen(req,timeout=timeout) as x: return json.loads(x.read().decode('utf-8','replace'))

def rdap_registrar(d):
    for e in d.get('entities',[]) or []:
        if 'registrar' in (e.get('roles') or []):
            for f in ((e.get('vcardArray') or [None,[]])[1] or []):
                if f and f[0]=='fn': return str(f[3])[:120]
    return None
def rdap_domain(domain):
    try:
        d=http_json('https://rdap.org/domain/'+urllib.parse.quote(domain)); return {'handle':d.get('handle'),'ldhName':d.get('ldhName'),'registrar':rdap_registrar(d),'status':d.get('status',[]),'events':d.get('events',[])[:6],'nameservers':[n.get('ldhName') for n in d.get('nameservers',[])[:10]]}
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

def indicators(r):
    return set(['domain:'+x for x in r.get('domains',[])]+['ip:'+x for x in r.get('ips',[])]+['url:'+x for x in r.get('urls',[])]+['sha256:'+a['sha256'] for a in r.get('attachments',[])])
def correlations(cid, cases=None):
    base=get_case(cid); bi=indicators(base); matches=[]
    for r in (cases if cases is not None else all_cases()):
        if r.get('case_id')==cid: continue
        shared=sorted(bi & indicators(r))
        if shared: matches.append({'case_id':r['case_id'],'subject':r.get('headers',{}).get('Subject',''),'severity':r.get('severity'),'risk_score':r.get('risk_score'),'status':r.get('status'),'created_utc':r.get('created_utc'),'shared_count':len(shared),'shared_indicators':shared[:50]})
    return sorted(matches,key=lambda x:x['shared_count'],reverse=True)
def graph_for(r):
    nodes=[]; edges=[]; seen=set()
    def node(i,label,t):
        if i not in seen: seen.add(i); nodes.append({'id':i,'label':label,'type':t})
    def edge(s,t,rel): edges.append({'source':s,'target':t,'relation':rel})
    cid='case:'+r['case_id']; node(cid,r['case_id'],'case'); sender=r.get('headers',{}).get('From','')
    if sender: node('sender:'+sender,sender,'sender'); edge(cid,'sender:'+sender,'received-from')
    for d in r.get('domains',[]): node('domain:'+d,d,'domain'); edge(cid,'domain:'+d,'observed')
    for u in r.get('urls',[]):
        node('url:'+u,u,'url'); edge(cid,'url:'+u,'contains'); h=urlparse(u).hostname
        if h: node('domain:'+h.lower(),h.lower(),'domain'); edge('url:'+u,'domain:'+h.lower(),'hosted-on')
    for ip in r.get('ips',[]): node('ip:'+ip,ip,'ip'); edge(cid,'ip:'+ip,'observed')
    for a in r.get('attachments',[]): node('hash:'+a['sha256'],a['filename'],'attachment'); edge(cid,'hash:'+a['sha256'],'attachment')
    for d,e in (r.get('enrichment') or {}).items():
        for n in (e.get('certificates') or {}).get('names',[])[:25]:
            if n!=d: node('domain:'+n,n,'related-domain'); edge('domain:'+d,'domain:'+n,'certificate-name')
    return {'nodes':nodes,'edges':edges}
def metrics():
    cs=all_cases(); ioc=Counter()
    for r in cs: ioc.update(indicators(r))
    return {'total_cases':len(cs),'severity':dict(Counter(r.get('severity','unknown') for r in cs)),'status':dict(Counter(r.get('status','new') for r in cs)),
            'total_unique_iocs':len(ioc),'reused_iocs':sum(1 for n in ioc.values() if n>1),'top_iocs':[{'indicator':k,'cases':v} for k,v in ioc.most_common(10) if v>1]}
def report_html(r):
    esc=lambda x: html.escape(str(x if x is not None else '')); li=lambda items,empty: ''.join(f'<li>{x}</li>' for x in items) or f'<li class=m>{empty}</li>'
    h=r.get('headers',{}); signals=r.get('signals') or [{'text':t,'points':None} for t in r.get('findings',[])]
    sig=li([esc(s['text'])+(f' <b>+{esc(s["points"])}</b>' if s.get('points') is not None else '') for s in signals],'No heuristic findings')
    iocs=li([f'<code>{esc(x)}</code>' for x in sorted(indicators(r))],'None')
    corr=li([f'{esc(x["case_id"])} ({esc(x["severity"])}) — {x["shared_count"]} shared IOC(s)' for x in correlations(r['case_id'])],'No correlated cases')
    mitre=li([esc(x['id'])+' — '+esc(x['name']) for x in r.get('mitre',[])],'None')
    notes=li([esc(n.get('created_utc'))+': '+esc(n.get('text')) for n in r.get('notes',[])],'None')
    tags=', '.join(esc(t) for t in r.get('tags',[])) or 'none'
    return f'''<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>PhishScope {esc(r['case_id'])}</title>
<style>body{{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;max-width:900px;margin:40px auto;padding:0 16px;color:#17202a;background:#fff;line-height:1.45}}h1{{border-bottom:3px solid #17202a;padding-bottom:10px}}.score{{font-size:28px;font-weight:bold}}code{{word-break:break-all}}.m{{color:#6c7f92}}@media print{{button{{display:none}}}}</style>
<button onclick="print()">Print / Save PDF</button><h1>PhishScope Investigation Report</h1>
<p><b>Case:</b> {esc(r['case_id'])}<br><b>Subject:</b> {esc(h.get('Subject'))}<br><b>From:</b> {esc(h.get('From'))}<br><b>Created:</b> {esc(r.get('created_utc'))}<br><b>Status:</b> {esc(r.get('status'))}<br><b>Tags:</b> {tags}<br><b>Evidence SHA-256:</b> <code>{esc(r.get('file_sha256'))}</code></p>
<p class=score>Risk {esc(r.get('risk_score'))}/100 — {esc(str(r.get('severity','')).upper())}</p>
<h2>Findings</h2><ul>{sig}</ul><h2>Indicators</h2><ul>{iocs}</ul><h2>MITRE ATT&amp;CK</h2><ul>{mitre}</ul><h2>Cross-case correlation</h2><ul>{corr}</ul><h2>Analyst notes</h2><ul>{notes}</ul>
<hr><small>Generated by PhishScope v{VERSION}. Defensive research only.</small></html>'''

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

CASE_ID_RE=re.compile(r'[A-Za-z0-9_-]{1,64}')
SEV_RANK=('critical','high','medium','low')
def case_ref(r): return {'case_id':r['case_id'],'subject':r.get('headers',{}).get('Subject',''),'severity':r.get('severity'),'status':r.get('status','new')}
def registration_date(rd):
    for e in rd.get('events') or []:
        if e.get('eventAction')=='registration': return str(e.get('eventDate',''))[:10] or None
    return None
def intel(cases=None):
    cs=cases if cases is not None else all_cases(); doms={}; today=datetime.datetime.now(datetime.timezone.utc).date()
    for r in cs:
        for d in r.get('domains',[]):
            e=doms.setdefault(d,{'cases':[],'enrichment':None,'enriched_utc':''}); e['cases'].append(case_ref(r))
            x=(r.get('enrichment') or {}).get(d); when=str(r.get('enriched_utc') or '')
            if x and (e['enrichment'] is None or when>=e['enriched_utc']): e['enrichment']=x; e['enriched_utc']=when  # newest lookup wins
    rows=[]
    for d,e in doms.items():
        x=e['enrichment'] or {}; rd=x.get('rdap') or {}; ct=x.get('certificates') or {}; vt=x.get('virustotal') or {}; reg=registration_date(rd); age=None
        if reg:
            try: age=(today-datetime.date.fromisoformat(reg)).days
            except ValueError: pass
        rows.append({'domain':d,'enriched':bool(x),'enriched_utc':e['enriched_utc'] or None,'rdap_error':rd.get('error'),'registered':reg,'age_days':age,'newly_registered':age is not None and age<30,
            'registrar':rd.get('registrar'),'status':rd.get('status',[]),'nameservers':sorted({str(n).lower() for n in rd.get('nameservers',[]) if n}),
            'ct_names':len(ct.get('names',[])),'ct_error':ct.get('error'),'vt_malicious':(vt.get('last_analysis_stats') or {}).get('malicious') if vt.get('configured') and not vt.get('error') else None,'cases':e['cases']})
    rows.sort(key=lambda r:(r['age_days'] is None,r['age_days'] or 0,r['domain']))
    shared=[]
    for kind,key in (('nameserver','nameservers'),('registrar','registrar')):
        m={}
        for r in rows:
            for v in (r[key] if isinstance(r[key],list) else [r[key]] if r[key] else []): m.setdefault(v,[]).append(r)
        for v,rs in m.items():
            if len(rs)>1: shared.append({'kind':kind,'value':v,'domains':[r['domain'] for r in rs],'cases':list({c['case_id']:c for r in rs for c in r['cases']}.values())})
    shared.sort(key=lambda x:(-len(x['domains']),x['kind'],x['value']))
    seen={}
    for r in cs:
        for i in indicators(r): seen.setdefault(i,[]).append(case_ref(r))
    recurring=sorted(({'indicator':i,'cases':c} for i,c in seen.items() if len(c)>1),key=lambda x:(-len(x['cases']),x['indicator']))
    return {'summary':{'domains':len(rows),'enriched':sum(r['enriched'] for r in rows),'newly_registered':sum(r['newly_registered'] for r in rows),
                       'shared_nameservers':sum(x['kind']=='nameserver' for x in shared),'recurring_indicators':len(recurring)},
            'domains':rows,'shared_infrastructure':shared,'recurring_indicators':recurring}

def sender_address(r): a=parseaddr(r.get('headers',{}).get('From',''))[1].lower(); return a if '@' in a else ''
def merged_iocs(cs):
    return {'senders':sorted({sender_address(r) for r in cs}-{''}),'domains':sorted({d for r in cs for d in r.get('domains',[])}),'ips':sorted({i for r in cs for i in r.get('ips',[])}),
            'hashes':sorted({a['sha256'] for r in cs for a in r.get('attachments',[])}),'mitre':sorted({m['id'] for r in cs for m in r.get('mitre',[])})}
def worst_severity(cs): return next((s for s in SEV_RANK if any(r.get('severity')==s for r in cs)),'medium')
def combined_sigma(cs):
    m=merged_iocs(cs); ids=[r['case_id'] for r in cs]; sel=[]
    if m['senders']: sel.append(('sender','    sender|contains:\n'+''.join('      - '+json.dumps(x)+'\n' for x in m['senders'])))
    if m['domains']: sel.append(('url','    url_domain|contains:\n'+''.join('      - '+json.dumps(x)+'\n' for x in m['domains'])))
    if not sel: sel=[('selection','    url_domain|contains:\n      - "none"\n')]
    tags=''.join('  - '+t+'\n' for t in ['attack.initial_access']+['attack.'+x.lower() for x in m['mitre']])
    return ("title: PhishScope combined indicators (%d case%s)\nid: %s\nstatus: experimental\ndescription: Indicators merged from authorized defensive phishing investigations %s\ndate: %s\ntags:\n%slogsource:\n  category: email\ndetection:\n%s  condition: %s\nfalsepositives:\n  - Legitimate messages sharing infrastructure\nlevel: %s\n"
            %(len(cs),'' if len(cs)==1 else 's',uuid.uuid5(uuid.NAMESPACE_DNS,'combined:'+','.join(sorted(ids))),', '.join(ids),datetime.date.today().strftime('%Y/%m/%d'),tags,''.join(f'  {k}:\n{v}' for k,v in sel),' or '.join(k for k,_ in sel),worst_severity(cs)))
def combined_yara(cs):
    m=merged_iocs(cs)
    strings=[f'    $domain{i} = "{d}" ascii wide nocase' for i,d in enumerate(m['domains'])]+[f'    $sender{i} = "{d}" ascii wide nocase' for i,d in enumerate(m['senders'])]+[f'    $hash{i} = "{h}" ascii' for i,h in enumerate(m['hashes'])]
    if not strings: strings=[f'    $case{i} = "{r["case_id"]}" ascii' for i,r in enumerate(cs)]
    return ('rule PhishScope_Combined_'+datetime.date.today().strftime('%Y%m%d')+' {\n  meta:\n    description = "Indicators merged from %d defensive PhishScope case%s"\n    cases = "%s"\n    severity = "%s"\n  strings:\n'
            %(len(cs),'' if len(cs)==1 else 's',', '.join(r['case_id'] for r in cs),worst_severity(cs))+'\n'.join(strings)+'\n  condition:\n    any of them\n}\n')
def combined_stix(cs):
    m=merged_iocs(cs); now=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    def ind(key,name,pattern,hit): return {'type':'indicator','spec_version':'2.1','id':'indicator--'+str(uuid.uuid5(uuid.NAMESPACE_DNS,key)),'created':now,'modified':now,'name':name,
        'description':'Seen in PhishScope cases: '+', '.join(r['case_id'] for r in cs if hit(r)),'indicator_types':['malicious-activity'],'pattern_type':'stix','pattern':pattern,'valid_from':now}
    objs=[ind('domain:'+d,'PhishScope domain indicator',f"[domain-name:value = '{d}']",lambda r,d=d:d in r.get('domains',[])) for d in m['domains']]
    objs+=[ind('ip:'+ip,'PhishScope IP indicator',f"[ipv4-addr:value = '{ip}']",lambda r,ip=ip:ip in r.get('ips',[])) for ip in m['ips']]
    objs+=[ind('sha256:'+h,'PhishScope attachment indicator',f"[file:hashes.'SHA-256' = '{h}']",lambda r,h=h:any(a['sha256']==h for a in r.get('attachments',[]))) for h in m['hashes']]
    return {'type':'bundle','id':'bundle--'+str(uuid.uuid4()),'objects':objs}

@app.get('/',response_class=HTMLResponse)
def home(): return (ROOT/'frontend'/'index.html').read_text()
@app.get('/api/health')
def health(): return {'name':'PhishScope','version':VERSION,'virustotal_configured':bool(os.getenv('VIRUSTOTAL_API_KEY'))}
@app.post('/api/analyze')
async def analyze(file:UploadFile=File(...)):
    if not (file.filename or '').lower().endswith('.eml'): raise HTTPException(400,'Upload an .eml file')
    data=await file.read()
    if len(data)>20*1024*1024: raise HTTPException(413,'File too large (20 MB max)')
    cid=datetime.datetime.now().strftime('%Y%m%d')+'-'+uuid.uuid4().hex[:8]; d=CASES/cid; d.mkdir(); (d/'original.eml').write_bytes(data)
    r=parse_eml(data,d); r.update({'case_id':cid,'filename':sanitize(file.filename),'file_sha256':sha256(data),'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'new','notes':[],'enrichment':{},'tags':[]}); save_case(r); return r
@app.get('/api/cases')
def cases():
    out=[]
    for r in all_cases():
        try:
            h=r.get('headers',{}); row={k:r.get(k) for k in ('case_id','filename','created_utc','risk_score','severity','status')}
            m=re.search(r'dmarc=(\w+)',h.get('Authentication-Results','').lower())
            row.update({'subject':h.get('Subject',''),'sender':h.get('From',''),'dmarc':m.group(1) if m else 'none','ioc_count':sum(len(r.get(k,[])) for k in ('urls','domains','ips','attachments')),'tags':r.get('tags',[])}); out.append(row)
        except: pass
    return out
@app.get('/api/metrics')
def dashboard_metrics(): return metrics()
@app.get('/api/cases/{case_id}')
def case(case_id:str): return get_case(case_id)
@app.get('/api/cases/{case_id}/graph')
def graph(case_id:str): return graph_for(get_case(case_id))
@app.get('/api/cases/{case_id}/correlations')
def corr(case_id:str): return correlations(case_id)
@app.get('/api/cases/{case_id}/report',response_class=HTMLResponse)
def report(case_id:str): return report_html(get_case(case_id))
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
@app.post('/api/cases/{case_id}/tags')
def tags(case_id:str,payload:dict=Body(...)):
    r=get_case(case_id); raw=payload.get('tags',[])
    if not isinstance(raw,list): raise HTTPException(400,'tags must be a list')
    r['tags']=sorted(set(str(x).strip()[:40] for x in raw if str(x).strip()))[:20]; save_case(r); return {'tags':r['tags']}
@app.get('/api/cases/{case_id}/sigma',response_class=PlainTextResponse)
def sigma(case_id:str): return sigma_for(get_case(case_id))
@app.get('/api/cases/{case_id}/yara',response_class=PlainTextResponse)
def yara(case_id:str): return yara_for(get_case(case_id))
@app.get('/api/cases/{case_id}/stix')
def stix(case_id:str): return stix_bundle(get_case(case_id))
@app.get('/api/intel')
def intel_rollup(): return intel()
@app.get('/api/detections')
def detections(cases:str='',format:str='sigma'):
    ids=list(dict.fromkeys(x.strip() for x in cases.split(',') if x.strip()))
    if format not in ('sigma','yara','stix'): raise HTTPException(400,'format must be sigma, yara or stix')
    if not ids: raise HTTPException(400,'Pass one or more case IDs: ?cases=id1,id2')
    if len(ids)>500 or not all(CASE_ID_RE.fullmatch(i) for i in ids): raise HTTPException(400,'Invalid case ID list')
    cs=[get_case(i) for i in ids]
    if format=='stix': return combined_stix(cs)
    return PlainTextResponse(combined_sigma(cs) if format=='sigma' else combined_yara(cs))
