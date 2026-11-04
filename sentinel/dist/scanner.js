export const supported = /\.(?:[cm]?[jt]sx?|py|rb|php|java|go|cs|json|ya?ml|toml|env|html|vue|svelte|sh|sql)$|(?:^|\/)\.env(?:\.|$)/i;
const excluded = /(?:^|\/)(?:node_modules|\.git|dist|build|vendor|coverage|\.next)\//;
export const rules = [
  {id:'SEC-001',severity:'Critical',category:'Secrets',title:'Possible private key in source',pattern:/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,why:'A private key may grant access to infrastructure or encrypted data.',fix:'Revoke and rotate this key. Remove it from source and repository history, and load the replacement from a secret manager.'},
  {id:'SEC-002',severity:'Critical',category:'Secrets',title:'Possible hardcoded credential',pattern:/(?:api[_-]?key|client[_-]?secret|access[_-]?token|password|secret[_-]?key)\s*[:=]\s*["'][^"'\s]{8,}["']/i,why:'A credential stored in source can be exposed through repository access or build output. Verify whether this is a real secret.',fix:'Rotate any real credential and move it to a secret manager or protected environment variable. Example placeholders may be false positives.'},
  {id:'SEC-003',severity:'Critical',category:'Secrets',title:'Possible AWS access key',pattern:/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,why:'An AWS access key identifier was found. Inspect access logs and verify its status.',fix:'Disable exposed credentials, rotate the key pair, and use short-lived workload identity.'},
  {id:'CODE-001',severity:'High',category:'Code security',title:'Dynamic code execution',pattern:/\b(?:eval|new\s+Function)\s*\(/,why:'Dynamic evaluation can execute attacker-controlled code when its input is untrusted. This pattern needs data-flow review.',fix:'Replace dynamic evaluation with structured parsing such as JSON.parse, or an allowlisted interpreter. Never evaluate untrusted input.'},
  {id:'CODE-002',severity:'High',category:'Code security',title:'Potential unsafe HTML injection',pattern:/\.innerHTML\s*=|dangerouslySetInnerHTML\s*=|\bdocument\.write\s*\(/,why:'Writing raw HTML can introduce cross-site scripting when values originate from untrusted input.',fix:'Prefer textContent or framework escaping. If HTML is necessary, sanitize it with a maintained HTML sanitizer and review the input source.'},
  {id:'CODE-003',severity:'High',category:'Code security',title:'TLS certificate verification disabled',pattern:/rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0/,why:'Disabling certificate checks can allow an attacker to intercept connections.',fix:'Enable certificate verification and install the correct trusted CA certificate.'},
  {id:'CODE-004',severity:'High',category:'Code security',title:'Possible command injection',pattern:/\b(?:exec|execSync|os\.system|subprocess\.call)\s*\([^\n]*(?:\+|\$\{|shell\s*=\s*True)/,why:'Building a shell command from variables may allow command injection. Review all input paths.',fix:'Use an argument-array API with shell disabled and validate inputs against an allowlist.'},
  {id:'CODE-005',severity:'Medium',category:'Code security',title:'Weak cryptographic hash',pattern:/createHash\s*\(\s*["'](?:md5|sha1)["']|hashlib\.(?:md5|sha1)\s*\(/i,why:'MD5 and SHA-1 are unsuitable for security-sensitive integrity checks. Context may make a non-security use acceptable.',fix:'Use SHA-256 or stronger for integrity, and a dedicated password hashing algorithm such as Argon2id for passwords.'},
  {id:'CODE-006',severity:'Medium',category:'Code security',title:'Potential insecure HTTP endpoint',pattern:/["'`]http:\/\/(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b|www\.w3\.org\b|schemas\.)[^\s"'`]+/,why:'Unencrypted HTTP may expose data in transit. Confirm this endpoint is used outside local development.',fix:'Use HTTPS and validate certificates for connections carrying sensitive information.'},
  {id:'CODE-007',severity:'Medium',category:'Code security',title:'Debug mode enabled',pattern:/\bDEBUG\s*=\s*True|app\.run\([^\n]*debug\s*=\s*True/,why:'Debug mode can expose stack traces, internals, or interactive consoles in production.',fix:'Disable debug mode in the production environment and configure centralized error logging.'}
];
export function scanSource(files) {
  const findings=[];let lines=0;let count=0;const warnings=[];const dependencies=new Map();
  const addDep=(name,version,path)=>{if(typeof version!=='string'||!name)return;const key=name+'@'+version;if(!dependencies.has(key))dependencies.set(key,{name,version,path,exact:/^\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?$/.test(version),status:'pending',latest:null,advisories:[]});};
  const locks=files.filter(f=>/(?:^|\/)package-lock\.json$/.test(f.path));
  for(const file of files){
    if(excluded.test(file.path)||!supported.test(file.path))continue;count++;
    const rows=file.content.split(/\r?\n/);lines+=rows.length;
    if(/(?:^|\/)(?:package|package-lock)\.json$/.test(file.path)){
      try {const j=JSON.parse(file.content);
        if(file.path.endsWith('package-lock.json')) {
          if(j.packages)for(const [p,v]of Object.entries(j.packages)){if(p&&p.includes('node_modules/')&&v.version)addDep(v.name||p.split('node_modules/').pop(),v.version,file.path);}
          else {const walk=d=>{for(const[n,v]of Object.entries(d||{})){addDep(n,v.version,file.path);walk(v.dependencies);}};walk(j.dependencies);}
        }else if(!locks.some(l=>l.path.replace(/package-lock\.json$/,'')===file.path.replace(/package\.json$/,''))){for(const[n,v]of Object.entries({...j.dependencies,...j.devDependencies}))addDep(n,v,file.path);}
      }catch{warnings.push('Could not parse '+file.path);}
      continue;
    }
    rows.forEach((line,index)=>{for(const rule of rules){if(rule.pattern.test(line))findings.push({...rule,pattern:undefined,uid:`${rule.id}-${file.path}-${index}`,path:file.path,line:index+1,snippet:rule.category==='Secrets'?'[Potential credential redacted]':line.trim().slice(0,500),status:'Open'});}});
  }
  if(!count)warnings.push('No supported source files found.');
  return {findings,files:count,lines,dependencies:[...dependencies.values()],warnings};
}
export async function fetchJSON(url,options={}) {
  const response=await fetch(url,{...options,signal:AbortSignal.timeout(15000)});
  if(!response.ok)throw new Error('Service returned '+response.status);
  return response.json();
}
const severityOrder=['Critical','High','Medium','Low','Unknown'];
function advisorySeverity(v){const s=v.database_specific?.severity||v.ecosystem_specific?.severity;if(s&&severityOrder.includes(s[0].toUpperCase()+s.slice(1).toLowerCase()))return s[0].toUpperCase()+s.slice(1).toLowerCase();return 'Unknown';}
async function queryAdvisories(dep){
  const vulns=[];let token;const seen=new Set();
  do {
    const data=await fetchJSON('https://api.osv.dev/v1/query',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({package:{name:dep.name,ecosystem:'npm'},version:dep.version,...(token?{page_token:token}:{})})});
    if(data.vulns!==undefined&&!Array.isArray(data.vulns))throw new Error('Invalid advisory response');
    vulns.push(...(data.vulns||[]));token=data.next_page_token;
    if(token){if(seen.has(token)||seen.size>=10)throw new Error('Advisory pagination could not complete');seen.add(token);}
  }while(token);
  return {vulns:[...new Map(vulns.map(v=>[v.id,v])).values()]};
}
export async function scanDependencies(dependencies,onProgress=()=>{}) {
  let done=0;const items=dependencies.slice(0,300);let cursor=0;
  async function worker(){while(cursor<items.length){const dep=items[cursor++];
    if(!dep.exact){dep.status='unresolved';done++;onProgress(done,items.length);continue;}
    const results=await Promise.allSettled([
      queryAdvisories(dep),
      fetchJSON('https://registry.npmjs.org/'+encodeURIComponent(dep.name)+'/latest')
    ]);
    dep.status=results[0].status==='fulfilled'?'checked':'unavailable';dep.advisories=[];
    if(results[0].status==='fulfilled')dep.advisories=(results[0].value.vulns||[]).filter(v=>!v.withdrawn).map(v=>({id:v.id,title:v.summary||v.id,severity:advisorySeverity(v),url:'https://osv.dev/vulnerability/'+encodeURIComponent(v.id),fixes:[...new Set((v.affected||[]).filter(a=>a.package?.name===dep.name).flatMap(a=>(a.ranges||[]).flatMap(r=>(r.events||[]).filter(e=>e.fixed).map(e=>e.fixed))))]}));
    if(results[1].status==='fulfilled')dep.latest=results[1].value.version;
    done++;onProgress(done,items.length);
  }}
  await Promise.all(Array.from({length:Math.min(6,items.length)},worker));
  for(const dep of dependencies.slice(300))dep.status='not checked';
  return dependencies.flatMap(dep=>dep.advisories.map(v=>({uid:'DEP-'+dep.name+'-'+dep.version+'-'+v.id,id:v.id,severity:v.severity,category:'Dependencies',title:v.title,path:dep.path,line:1,snippet:dep.name+'@'+dep.version,why:'OSV reports an advisory affecting this exact installed version. Review the advisory and your application’s use of the package.',fix:v.fixes.length?'Reported fixed versions: '+v.fixes.join(', ')+'. Select a compatible patched release, regenerate your lockfile, and run your tests.':'Review the linked advisory for mitigation or a supported replacement.',url:v.url,status:'Open'})));
}
export function isOutdated(dep){if(!dep.latest||!dep.exact)return false;const a=dep.version.split(/[.-]/).slice(0,3).map(Number),b=dep.latest.split(/[.-]/).slice(0,3).map(Number);for(let i=0;i<3;i++){if(b[i]>a[i])return true;if(b[i]<a[i])return false;}return false;}
export function releaseGate(scan,policy){
  if(!scan)return {state:'Not scanned',reason:'Run a scan to evaluate your code.'};
  const blockers=scan.findings.filter(f=>f.severity==='Critical'||(policy.blockHigh&&f.severity==='High')||f.severity==='Unknown');
  if(blockers.length)return {state:'Blocked',reason:`${blockers.length} finding${blockers.length===1?' needs':'s need'} review before release.`};
  if(scan.files===0||scan.warnings.length||scan.dependencies.some(d=>d.status!=='checked')||scan.truncated)return {state:'Incomplete',reason:'Some files or dependencies could not be checked.'};
  if(policy.blockOutdated&&scan.dependencies.some(isOutdated))return {state:'Blocked',reason:'Your policy requires dependency updates.'};
  if(scan.dependencies.some(d=>!d.latest)&&scan.dependencies.length&&policy.blockOutdated)return {state:'Incomplete',reason:'Latest package versions could not be verified.'};
  return {state:'Checks passed',reason:'No blocking findings in the checks performed. Tests and review are still required.'};
}
