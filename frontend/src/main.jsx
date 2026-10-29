import React,{useState} from 'react';
import {createRoot} from 'react-dom/client';
import './style.css';

const API = '';
const ident = {subject_id:'demo-alice',action:'transfer',currency:'USD',beneficiary_id:'new-beneficiary'};
function App(){
  const [apiKey,setApiKey]=useState('');
  const [amount,setAmount]=useState('15000');
  const [newDevice,setNewDevice]=useState(true);
  const [newBeneficiary,setNewBeneficiary]=useState(true);
  const [failures,setFailures]=useState(2);
  const [velocity,setVelocity]=useState(4);
  const [result,setResult]=useState(null);
  const [cases,setCases]=useState([]);
  const [events,setEvents]=useState([]);
  const [metrics,setMetrics]=useState(null);
  const [audit,setAudit]=useState(null);
  const [error,setError]=useState('');
  const [busy,setBusy]=useState(false);
  const [keyPair,setKeyPair]=useState(null);
  const [notice,setNotice]=useState('API key stays in browser memory; it is not persisted.');
  const headers={'Content-Type':'application/json','X-API-Key':apiKey};
  async function req(path,method='GET',body){
    const r=await fetch(API+path,{method,headers,body:body?JSON.stringify(body):undefined});
    const data=await r.json().catch(()=>({}));
    if(!r.ok) throw Error(data.detail||'Request failed ('+r.status+')');
    return data;
  }
  const intent=()=>({...ident,amount_minor:Math.round(Number(amount||0)*100)});
  async function refresh(){
    try{
      const [c,e,m,a]=await Promise.all([req('/v1/cases'),req('/v1/events'),req('/v1/metrics'),req('/v1/audit/verify')]);
      setCases(c.cases);setEvents(e.events);setMetrics(m);setAudit(a);
    }catch(e){setError(String(e.message))}
  }
  function b64(bytes){return btoa(String.fromCharCode(...new Uint8Array(bytes)))}
  async function registerDevice(){
    setError('');setBusy(true);
    try{
      if(!crypto.subtle)throw Error('Secure browser context required (localhost or HTTPS).');
      const pair=await crypto.subtle.generateKey({name:'Ed25519'},false,['sign','verify']);
      const pub=await crypto.subtle.exportKey('raw',pair.publicKey);
      const credential_id='browser-'+crypto.randomUUID();
      await req('/v1/credentials','POST',{subject_id:ident.subject_id,credential_id,ed25519_public_key_b64:b64(pub)});
      setKeyPair({privateKey:pair.privateKey,credential_id});
      setNotice('Ephemeral demo credential registered. Refreshing the page intentionally loses its private key. This is NOT WebAuthn.');
    }catch(e){setError(e.message)}finally{setBusy(false)}
  }
  async function run(signed=false){
    setBusy(true);setError('');
    try{
      const data={...intent(),request_id:crypto.randomUUID(),new_device:newDevice,known_device:!newDevice,
        recent_failed_attempts:Number(failures),velocity_1h:Number(velocity),newly_added_beneficiary:newBeneficiary};
      if(signed){
        if(!keyPair)throw Error('Register a demo signing credential first.');
        const challenge=await req('/v1/challenges','POST',intent());
        const bytes=new TextEncoder().encode(challenge.message_to_sign);
        const signature=await crypto.subtle.sign('Ed25519',keyPair.privateKey,bytes);
        Object.assign(data,{credential_id:keyPair.credential_id,challenge_id:challenge.challenge_id,signature_b64:b64(signature)});
      }
      setResult(await req('/v1/evaluate','POST',data));
      await refresh();
    }catch(e){setError(e.message)}finally{setBusy(false)}
  }
  async function updateCase(id,status){
    setError('');
    try{await req('/v1/cases/'+encodeURIComponent(id),'PATCH',{status,analyst_note:'Updated in demonstration console'});await refresh()}
    catch(e){setError(e.message)}
  }
  return <main>
    <header><div className="logo"><span>⬡</span> AEGIS <b>IDENTITY</b></div><span className="pill">DEVELOPMENT ENVIRONMENT</span></header>
    <section className="hero"><div className="eyebrow">ADAPTIVE EVIDENCE-GROUNDED IDENTITY SECURITY</div><h1>Identity continuity.<br/><em>Trust is earned, not assumed.</em></h1><p>Signed transaction authorization, contextual fraud risk, tenant-scoped evidence and investigation workflows. Synthetic users only.</p></section>
    <section className="connection panel"><div><h2>API access</h2><p>Run the backend with configured AEGIS_API_KEYS. Enter your demo administrator key to use the console.</p></div><input type="password" aria-label="API key" placeholder="Demo API key" value={apiKey} onChange={e=>setApiKey(e.target.value)}/><button className="secondary" disabled={!apiKey||busy} onClick={refresh}>Load investigations</button></section>
    <section className="grid">
      <article className="panel"><div className="heading"><h2>Transaction evaluation</h2><span>01 / RISK ENGINE</span></div>
        <label>Transfer amount (USD)</label><input type="number" min="0" max="10000000000" value={amount} onChange={e=>setAmount(e.target.value)}/>
        <div className="split"><label>Failed attempts<input type="number" min="0" max="10000" value={failures} onChange={e=>setFailures(e.target.value)}/></label><label>Velocity (1h)<input type="number" min="0" max="10000" value={velocity} onChange={e=>setVelocity(e.target.value)}/></label></div>
        <label className="toggle"><input type="checkbox" checked={newDevice} onChange={e=>setNewDevice(e.target.checked)}/> New or unfamiliar device</label>
        <label className="toggle"><input type="checkbox" checked={newBeneficiary} onChange={e=>setNewBeneficiary(e.target.checked)}/> Newly added beneficiary</label>
        <div className="actions"><button disabled={!apiKey||busy} onClick={()=>run(false)}>Evaluate unsigned</button><button className="secondary" disabled={!apiKey||busy} onClick={()=>run(true)}>Evaluate signed</button></div>
      </article>
      <article className="panel"><div className="heading"><h2>Decision engine</h2><span>02 / CONTINUITY</span></div>
        {result?<><div className="score">{result.risk_score}<small> / 100</small></div><div className={'decision '+result.decision}>{result.decision.toUpperCase()}</div><p className="muted">Risk score is an illustrative deterministic baseline, not a trained fraud probability.</p><div className="reasons">{result.reason_codes.map(x=><span key={x}>{x.replaceAll('_',' ')}</span>)}</div><p className="muted">Signature verified: <strong>{String(result.evidence.signature_verified)}</strong></p><code>{result.id}</code></>:<p className="empty">Run a transaction evaluation to inspect its policy decision, reason codes, and cryptographic authorization state.</p>}
      </article>
    </section>
    <section className="panel credential"><div><h2>Cryptographic credential lab</h2><p>Register an ephemeral browser Ed25519 key. Signed challenges bind the exact amount and beneficiary, with one-time replay protection.</p><small>{notice}</small></div><button disabled={!apiKey||busy} onClick={registerDevice}>{keyPair?'Replace demo credential':'Register demo credential'}</button></section>
    <section className="panel intelligence"><div className="heading"><h2>Security operations overview</h2><span>03 / TENANT TELEMETRY</span></div>
      <div className="metric-grid"><div><strong>{metrics?.counts?.allow ?? '—'}</strong><small>Allowed</small></div><div><strong>{metrics?.counts?.challenge ?? '—'}</strong><small>Challenged</small></div><div><strong>{metrics?.counts?.hold ?? '—'}</strong><small>Held</small></div><div><strong>{metrics?.open_cases ?? '—'}</strong><small>Open cases</small></div></div>
      <div className="audit-status">Audit chain: <strong>{audit ? (audit.valid ? 'PASS' : 'INTEGRITY ERROR') : 'NOT CHECKED'}</strong> {audit && <span> · {audit.checked} records · local hash chain, not externally anchored</span>}</div>
    </section>
    <section className="grid investigations">
      <article className="panel"><div className="heading"><h2>Investigation cases</h2><span>{cases.length} RECENT</span></div>{!cases.length?<p className="empty">No cases loaded. High-risk or unsigned decisions create cases.</p>:cases.map(c=><div className="item" key={c.id}><div><strong>{c.status.toUpperCase()}</strong><small>{c.id.slice(0,8)} · {c.created_at.slice(0,19)}</small></div><select aria-label="Case status" value={c.status} onChange={e=>updateCase(c.id,e.target.value)}><option value="open">Open</option><option value="investigating">Investigating</option><option value="escalated">Escalated</option><option value="resolved">Resolved</option></select></div>)}</article>
      <article className="panel"><div className="heading"><h2>Audit events</h2><span>{events.length} RECENT</span></div>{!events.length?<p className="empty">No audit events loaded.</p>:events.map(e=><div className="item" key={e.id}><div><strong>{e.action.toUpperCase()} · {e.decision.toUpperCase()}</strong><small>{e.subject_ref} · {e.timestamp.slice(0,19)}</small></div><strong>{e.risk_score}/100</strong></div>)}</article>
    </section>
    {error&&<div role="alert" className="error">{error}</div>}
    <footer>AEGIS IDENTITY v0.3 · Engineering prototype · No real ID data, banking rails or biometric verification · Ed25519 demo ≠ WebAuthn</footer>
  </main>;
}
createRoot(document.getElementById('root')).render(<App/>);
