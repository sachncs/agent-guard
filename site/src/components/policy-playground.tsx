import { useState } from 'react';
import { policy } from '../data/examples';
export function PolicyPlayground() {
 const [principal,setPrincipal] = useState('research');
 const [action,setAction] = useState('repo_read');
 const [resource,setResource] = useState('demo');
 const [mfa,setMfa] = useState('true');
 const checks = [[principal==='research','Principal is research'],[action==='repo_read','Action is repo_read'],[resource==='demo','Resource is demo'],[mfa==='true','Session has MFA']] as const;
 const allowed = checks.every(([matches]) => matches);
 const request = {subject:{type:'Agent',id:principal},action:{type:'Action',id:`ToolCall::${action}`},resource:{type:'Repository',id:resource},context:{args:{repo:resource,...(action==='repo_write'?{branch:'main'}:{})},session:{mfa:mfa==='true'}}};
 return <section className="section" id="playground"><div className="container">
 <div className="section-heading"><div><span className="section-kicker">11 / EXPLORE A DECISION</span><h2>A small policy.<br/><span>A visible boundary.</span></h2></div><p>Change a request and inspect the result. This browser simulation checks the four conditions below in JavaScript. It does not execute Cedar, contact a server, or create an audit record.</p></div>
 <div className="playground-grid"><div><div className="playground-controls">
 <label>Principal<select value={principal} onChange={e=>setPrincipal(e.target.value)}><option value="research">research</option><option value="summarizer">summarizer</option></select></label>
 <label>Action<select value={action} onChange={e=>setAction(e.target.value)}><option value="repo_read">repo_read</option><option value="repo_write">repo_write</option></select></label>
 <label>Resource<select value={resource} onChange={e=>setResource(e.target.value)}><option value="demo">Repository::demo</option><option value="private">Repository::private</option></select></label>
 <label>MFA state<select value={mfa} onChange={e=>setMfa(e.target.value)}><option value="true">Verified</option><option value="false">Not verified</option></select></label>
 </div><div className="playground-policy"><span className="caption">The only policy in this simulation</span><pre><code>{policy}</code></pre></div><button className="button small" onClick={()=>{setPrincipal('research');setAction('repo_read');setResource('demo');setMfa('true');}}>Reset request</button></div>
 <div className="playground-result" data-denied={!allowed}><div aria-live="polite" aria-atomic="true"><span className="caption">Illustrative decision</span><h3>{allowed?'ALLOW':'DENY'}</h3><p>{allowed?'All permit conditions match. The adapter may execute the tool.':'No permit matches. The adapter must stop the tool call.'}</p><ul>{checks.map(([matches,label])=><li key={label}>{matches?'✓':'×'} {label} — {matches?'matches':'does not match'}</li>)}</ul></div>
 <details><summary>Inspect authorization request</summary><pre>{JSON.stringify(request,null,2)}</pre></details><details><summary>Inspect sample audit fields</summary><p>Illustrative fields only. No signature or chain is generated here.</p><pre>{JSON.stringify({effect:allowed?'allow':'deny',principal,action,resource,policies:allowed?['example-permit']:[],timestamp:'illustrative timestamp'},null,2)}</pre></details>
 <a className="text-link" href={`${import.meta.env.BASE_URL}docs/getting-started/`}>Run this policy with real Cedar →</a></div></div></div></section>;
}
