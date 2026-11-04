import {test} from 'node:test';
import assert from 'node:assert/strict';
import {scanSource,scanDependencies,releaseGate,isOutdated} from '../dist/scanner.js';

test('credential excerpts are redacted and generated folders are excluded',()=>{
  const s=scanSource([{path:'src/auth.ts',content:'const client_secret = "never-save-this-value";\neval(userInput)'},{path:'node_modules/pkg/index.js',content:'eval(input)'}]);
  assert.equal(s.files,1);assert.equal(s.findings.length,2);
  assert.ok(!JSON.stringify(s).includes('never-save-this-value'));
  assert.equal(releaseGate(s,{blockHigh:true}).state,'Blocked');
});
test('npm lockfiles resolve transitive and scoped packages; range-only manifests remain incomplete',()=>{
  const s=scanSource([{path:'package.json',content:'{"dependencies":{"lodash":"^4.0.0"}}'},{path:'package-lock.json',content:JSON.stringify({packages:{'':{name:'app'},'node_modules/lodash':{version:'4.17.20'},'node_modules/parent/node_modules/@scope/pkg':{version:'1.0.0'}}})}]);
  assert.deepEqual(s.dependencies.map(d=>[d.name,d.version]),[['lodash','4.17.20'],['@scope/pkg','1.0.0']]);
  const unresolved=scanSource([{path:'package.json',content:'{"dependencies":{"lodash":"^4.0.0"}}'}]);
  assert.equal(unresolved.dependencies[0].exact,false);assert.equal(releaseGate(unresolved,{}).state,'Incomplete');
});
test('malformed manifests and empty scans cannot pass',()=>{
  const malformed=scanSource([{path:'package.json',content:'{'}]);
  assert.equal(releaseGate(malformed,{}).state,'Incomplete');
  assert.equal(releaseGate(scanSource([]),{}).state,'Incomplete');
});
test('advisory pagination completes, withdrawn records are ignored, and failures cannot pass',async()=>{
  const original=globalThis.fetch;let queries=0;
  try {
    globalThis.fetch=async(url,options)=>({ok:true,json:async()=>{
      if(url.includes('registry'))return {version:'4.17.21'};
      queries++;const body=JSON.parse(options.body);
      return body.page_token?{vulns:[{id:'WITHDRAWN',withdrawn:'2025-01-01'}]}:{vulns:[{id:'GHSA-test',summary:'Test issue',database_specific:{severity:'HIGH'},affected:[{package:{name:'lodash'},ranges:[{events:[{fixed:'4.17.21'}]}]}]}],next_page_token:'page-2'};
    }});
    const s=scanSource([{path:'package.json',content:'{"dependencies":{"lodash":"4.17.20"}}'}]);
    const findings=await scanDependencies(s.dependencies);assert.equal(queries,2);assert.equal(findings.length,1);assert.equal(findings[0].severity,'High');assert.match(findings[0].fix,/4\.17\.21/);assert.equal(isOutdated(s.dependencies[0]),true);
    globalThis.fetch=async()=>{throw new Error('offline')};
    await scanDependencies(s.dependencies);assert.equal(s.dependencies[0].status,'unavailable');assert.equal(s.dependencies[0].advisories.length,0);assert.equal(releaseGate(s,{}).state,'Incomplete');
  }finally{globalThis.fetch=original;}
});
test('unknown severity blocks release and passing checks retain review limitations',()=>{
  const s=scanSource([{path:'app.js',content:'const value = 42;'}]);assert.equal(releaseGate(s,{}).state,'Checks passed');
  s.findings.push({severity:'Unknown'});assert.equal(releaseGate(s,{}).state,'Blocked');
});
