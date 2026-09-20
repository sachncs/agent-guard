import { useState } from "react";

export function PolicyPlayground() {
  const [agent, setAgent] = useState("support-copilot");
  const [action, setAction] = useState("tickets.read");
  const [environment, setEnvironment] = useState("production");
  const allowed = agent === "support-copilot" && action !== "secrets.read" && environment === "production";
  const reasons = [
    [agent === "support-copilot", "Principal is support-copilot"],
    [action !== "secrets.read", "Action is tickets.read or tickets.update"],
    [environment === "production", "Environment is production"],
  ] as const;
  return (
    <section className="section container" id="playground">
      <div className="section-intro">
        <div><span className="section-kicker">TRY THE BOUNDARY</span><h2>Change the request.<br /><span>See the decision.</span></h2></div>
        <p>Explore the policy above. This browser illustration evaluates its three conditions locally; it does not run Cedar or contact a policy server.</p>
      </div>
      <div className="playground-grid">
        <div className="playground-controls">
          <label htmlFor="demo-principal">Principal<select id="demo-principal" value={agent} onChange={e => setAgent(e.target.value)}><option>support-copilot</option><option>research-bot</option></select></label>
          <label htmlFor="demo-action">Action<select id="demo-action" value={action} onChange={e => setAction(e.target.value)}><option>tickets.read</option><option>tickets.update</option><option>secrets.read</option></select></label>
          <label htmlFor="demo-environment">Environment<select id="demo-environment" value={environment} onChange={e => setEnvironment(e.target.value)}><option>production</option><option>staging</option></select></label>
          <button className="button button-ghost" onClick={() => { setAgent("support-copilot"); setAction("tickets.read"); setEnvironment("production"); }}>Reset example</button>
        </div>
        <div className="playground-result" aria-live="polite" aria-atomic="true">
          <span className="section-kicker">ILLUSTRATIVE RESULT</span>
          <h3>{allowed ? "ALLOW" : "DENY"}</h3>
          <p>{allowed ? "All permit conditions match. The tool adapter can proceed." : "No permit matches this request. The tool adapter must stop execution."}</p>
          <ul>{reasons.map(([matches, label]) => <li key={label}>{matches ? "✓" : "×"} {label} — {matches ? "matches" : "does not match"}</li>)}</ul>
          <a className="inline-link" href={import.meta.env.BASE_URL + "docs/api/"}>Connect a real policy server →</a>
        </div>
      </div>
    </section>
  );
}
