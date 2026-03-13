/**
 * OrgForge Demo API — Phase 0
 *
 * Zero dependencies. Pure Node built-ins. Railway-ready.
 * Start: node server.js
 */

'use strict';

const http = require('http');
const crypto = require('crypto');
const url = require('url');

const PORT = process.env.PORT || 3000;

// ─── OrgSpec ────────────────────────────────────────────────────────────────

const ORGSPEC = {
  org_id: 'org:demo',
  orgspec_version: 'v0',
  roles: {
    trainer_agent: {
      allowed_action_types: ['TOOL_CALL'],
      allowed_tools: ['search', 'summarize', 'draft', 'code_exec'],
      max_calls_per_minute: 20,
      episode_budget_units: 1000,
      requires_approval: ['code_exec']
    },
    trader_agent: {
      allowed_action_types: ['PLACE_ORDER'],
      allowed_markets: ['ETH-USD', 'BTC-USD'],
      max_order_notional_usd: 10000,
      max_daily_notional_usd: 50000,
      max_trades_per_minute: 10,
      approval_threshold_usd: 10000
    },
    treasury_bot: {
      allowed_action_types: ['PLACE_ORDER', 'TOOL_CALL'],
      allowed_markets: ['ETH-USD', 'BTC-USD', 'SOL-USD'],
      max_order_notional_usd: 5000,
      max_daily_notional_usd: 10000,
      max_trades_per_minute: 5,
      approval_threshold_usd: 7500,
      allowed_tools: ['search', 'summarize'],
      max_calls_per_minute: 10,
      episode_budget_units: 500,
      requires_approval: []
    }
  },
  actors: {
    'agent:alpha': { role: 'trainer_agent', label: 'Training Agent Alpha', active: true },
    'agent:trader_1': { role: 'trader_agent', label: 'Primary Trading Bot', active: true },
    'agent:trader_suspended': { role: 'trader_agent', label: 'Suspended Trading Bot', active: false }
  }
};

// ─── Primitives ─────────────────────────────────────────────────────────────

const REASON = {
  OK: 'OK',
  ERR_EXPIRED_INTENT: 'ERR_EXPIRED_INTENT',
  ERR_UNKNOWN_ACTOR: 'ERR_UNKNOWN_ACTOR',
  ERR_SUSPENDED_ACTOR: 'ERR_SUSPENDED_ACTOR',
  ERR_ROLE_NOT_FOUND: 'ERR_ROLE_NOT_FOUND',
  ERR_ACTION_NOT_ALLOWED: 'ERR_ACTION_NOT_ALLOWED',
  ERR_TOOL_NOT_ALLOWED: 'ERR_TOOL_NOT_ALLOWED',
  ERR_MARKET_NOT_ALLOWED: 'ERR_MARKET_NOT_ALLOWED',
  ERR_MAX_ORDER_EXCEEDED: 'ERR_MAX_ORDER_EXCEEDED',
  ERR_APPROVAL_REQUIRED: 'ERR_APPROVAL_REQUIRED',
  ERR_INVALID_PARAMS: 'ERR_INVALID_PARAMS',
  ERR_INTERNAL: 'ERR_INTERNAL'
};

function canonical_json(obj) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return JSON.stringify(obj);
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => `${JSON.stringify(k)}:${canonical_json(obj[k])}`).join(',') + '}';
}

function intent_hash(intent) {
  return '0x' + crypto.createHash('sha256').update(Buffer.from(canonical_json(intent), 'utf8')).digest('hex');
}

function sign_proof(validator_id, fields) {
  const signing_key = crypto.createHash('sha256').update(validator_id).digest();
  const digest = '0x' + crypto.createHash('sha256').update(Buffer.from(canonical_json(fields), 'utf8')).digest('hex');
  return '0x' + crypto.createHmac('sha256', signing_key).update(digest).digest('hex');
}

// ─── Policy Evaluation ──────────────────────────────────────────────────────

function fail_step(steps, stage, detail) {
  const labels = {
    validate: 'Intent structure', actor: 'Actor & role',
    freshness: 'Intent freshness', policy: 'Action policy', approval: 'Approval gate'
  };
  steps.push({ stage, label: labels[stage] || stage, result: 'fail', detail });
  return { authorized: false, steps, reason_code: 'ERR_' + stage.toUpperCase(), detail };
}

function evaluate_intent(intent, orgspec) {
  const steps = [];
  const now = Math.floor(Date.now() / 1000);

  // 1. Structural validation
  for (const f of ['org_id', 'actor_id', 'action_type', 'params', 'nonce', 'expires_at']) {
    if (intent[f] === undefined || intent[f] === null || intent[f] === '') {
      return fail_step(steps, 'validate', `Missing required field: ${f}`);
    }
  }
  steps.push({ stage: 'validate', label: 'Intent structure', result: 'pass', detail: 'All required fields present' });

  // 2. Actor lookup
  const actor = orgspec.actors[intent.actor_id];
  if (!actor) return fail_step(steps, 'actor', `Actor '${intent.actor_id}' not found in OrgSpec`);
  if (actor.active === false) return fail_step(steps, 'actor', `Actor '${intent.actor_id}' is suspended`);
  const role = orgspec.roles[actor.role];
  if (!role) return fail_step(steps, 'actor', `Role '${actor.role}' not defined`);
  steps.push({ stage: 'actor', label: 'Actor & role', result: 'pass', detail: `${actor.label} \u2192 role: ${actor.role}` });

  // 3. Freshness
  if (intent.expires_at < now) return fail_step(steps, 'freshness', `Intent expired ${now - intent.expires_at}s ago`);
  steps.push({ stage: 'freshness', label: 'Intent freshness', result: 'pass', detail: `Expires in ${intent.expires_at - now}s` });

  // 4. Action policy
  if (role.allowed_action_types && !role.allowed_action_types.includes(intent.action_type)) {
    return fail_step(steps, 'policy', `Role '${actor.role}' cannot perform '${intent.action_type}'`);
  }

  if (intent.action_type === 'TOOL_CALL') {
    const p = intent.params;
    if (!p.tool || p.cost_units === undefined || !p.payload_hash) {
      return fail_step(steps, 'policy', 'TOOL_CALL missing required params (tool, cost_units, payload_hash)');
    }
    if (role.allowed_tools && !role.allowed_tools.includes(p.tool)) {
      return fail_step(steps, 'policy', `Tool '${p.tool}' not in allowed list: [${role.allowed_tools.join(', ')}]`);
    }
    steps.push({ stage: 'policy', label: 'Action policy', result: 'pass', detail: `Tool '${p.tool}' permitted for role '${actor.role}'` });

    // 5. Approval
    if (role.requires_approval && role.requires_approval.includes(p.tool)) {
      if (!p.approvals || p.approvals.approvals_met !== true) {
        return fail_step(steps, 'approval', `Tool '${p.tool}' requires human approval \u2014 none provided`);
      }
      steps.push({ stage: 'approval', label: 'Approval gate', result: 'pass', detail: `Human approval confirmed for '${p.tool}'` });
    } else {
      steps.push({ stage: 'approval', label: 'Approval gate', result: 'pass', detail: `No approval required for '${p.tool}'` });
    }
  }

  if (intent.action_type === 'PLACE_ORDER') {
    const p = intent.params;
    for (const f of ['venue', 'market', 'side', 'type', 'notional_usd']) {
      if (p[f] === undefined) return fail_step(steps, 'policy', `PLACE_ORDER missing param: ${f}`);
    }
    if (!['BUY', 'SELL'].includes(p.side)) return fail_step(steps, 'policy', 'side must be BUY or SELL');
    if (role.allowed_markets && !role.allowed_markets.includes(p.market)) {
      return fail_step(steps, 'policy', `Market '${p.market}' not in allowed list: [${role.allowed_markets.join(', ')}]`);
    }
    if (role.max_order_notional_usd !== undefined && p.notional_usd > role.max_order_notional_usd) {
      return fail_step(steps, 'policy', `$${p.notional_usd.toLocaleString()} exceeds per-order limit of $${role.max_order_notional_usd.toLocaleString()}`);
    }
    steps.push({ stage: 'policy', label: 'Action policy', result: 'pass',
      detail: `${p.side} ${p.market} $${p.notional_usd.toLocaleString()} \u2014 within limits` });

    // 5. Approval
    if (role.approval_threshold_usd !== undefined && p.notional_usd > role.approval_threshold_usd) {
      if (!p.approvals || p.approvals.approvals_met !== true) {
        return fail_step(steps, 'approval', `$${p.notional_usd.toLocaleString()} exceeds approval threshold of $${role.approval_threshold_usd.toLocaleString()}`);
      }
      steps.push({ stage: 'approval', label: 'Approval gate', result: 'pass', detail: 'Human approval confirmed' });
    } else {
      steps.push({ stage: 'approval', label: 'Approval gate', result: 'pass', detail: 'Below approval threshold' });
    }
  }

  return { authorized: true, steps, reason_code: REASON.OK };
}

function assemble_proof(intent, orgspec) {
  const now = Math.floor(Date.now() / 1000);
  if (!intent.expires_at || intent.expires_at < now) intent.expires_at = now + 300;
  if (!intent.nonce) intent.nonce = crypto.randomBytes(8).toString('hex');

  const result = evaluate_intent(intent, orgspec);
  const hash = intent_hash(intent);

  if (!result.authorized) return { ...result, intent_hash: hash, decision: 'REJECTED' };

  const proof_fields = {
    decision: 'AUTHORIZED',
    expires_at: now + 300,
    intent_hash: hash,
    issued_at: now,
    org_id: intent.org_id,
    orgspec_version: orgspec.orgspec_version,
    validator_set_id: 'set:demo-v0'
  };

  const quorum_signatures = ['validator:node-A', 'validator:node-B'].map(v => ({
    validator: v,
    sig: sign_proof(v, proof_fields)
  }));

  return { ...result, decision: 'AUTHORIZED', intent_hash: hash, proof: { ...proof_fields, quorum_signatures, threshold: '2-of-3' } };
}

// ─── HTTP Helpers ────────────────────────────────────────────────────────────

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => { try { resolve(JSON.parse(body)); } catch (e) { reject(e); } });
  });
}

function send(res, status, obj, contentType) {
  const body = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
  res.writeHead(status, {
    'Content-Type': contentType || 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
  });
  res.end(body);
}

// ─── Demo UI HTML ─────────────────────────────────────────────────────────────

const DEMO_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OrgForge \u2014 Live Demo</title>
<style>
:root{--bg:#0c1020;--surface:#141826;--surface2:#1a2035;--border:#2a3350;--gold:#d4af37;--cyan:#22d3ee;--green:#34d399;--red:#f87171;--text:#e2e8f0;--muted:#64748b;--mono:'SF Mono','Fira Code','Cascadia Code',monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;min-height:100vh;display:flex;flex-direction:column}
header{border-bottom:1px solid var(--border);padding:16px 32px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.logo{font-size:18px;font-weight:700;letter-spacing:-0.5px}.logo span{color:var(--gold)}
.badge{font-size:11px;font-family:var(--mono);color:var(--cyan);border:1px solid var(--cyan);padding:2px 10px;border-radius:4px;opacity:.8}
.layout{display:grid;grid-template-columns:400px 1fr;flex:1;overflow:hidden}
.left{border-right:1px solid var(--border);overflow-y:auto;padding:24px;display:flex;flex-direction:column;gap:20px}
.right{padding:28px 32px;overflow-y:auto;display:flex;flex-direction:column;gap:24px}
.slabel{font-size:11px;font-family:var(--mono);color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:10px}
.scenarios{display:flex;flex-direction:column;gap:8px}
.sc{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:10px 14px;border-radius:6px;cursor:pointer;text-align:left;font-size:13px;transition:border-color .15s,background .15s}
.sc:hover{border-color:var(--cyan);background:var(--surface2)}
.sc.active{border-color:var(--gold);background:var(--surface2)}
.sc-name{font-weight:600;display:block;margin-bottom:2px}
.sc-desc{font-size:11px;color:var(--muted);font-family:var(--mono)}
.tag{display:inline-block;font-size:10px;font-family:var(--mono);padding:1px 6px;border-radius:3px;margin-left:6px;vertical-align:middle}
.tag.p{background:rgba(52,211,153,.15);color:var(--green)}
.tag.f{background:rgba(248,113,113,.15);color:var(--red)}
textarea{width:100%;height:200px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--cyan);font-family:var(--mono);font-size:12px;padding:12px;resize:vertical;outline:none;line-height:1.5}
textarea:focus{border-color:var(--gold)}
.btn{width:100%;background:var(--gold);color:#0c1020;border:none;padding:12px;border-radius:6px;font-weight:700;font-size:14px;cursor:pointer;letter-spacing:.3px;transition:opacity .15s}
.btn:hover{opacity:.9}.btn:disabled{opacity:.5;cursor:not-allowed}
.ptitle{font-size:12px;color:var(--muted);font-family:var(--mono);margin-bottom:4px}
.pipeline{display:flex;flex-direction:column}
.stage{display:flex;align-items:flex-start;gap:16px;padding:14px 0;position:relative}
.stage:not(:last-child)::after{content:'';position:absolute;left:19px;top:46px;bottom:0;width:2px;background:var(--border)}
.sico{width:40px;height:40px;border-radius:50%;background:var(--surface);border:2px solid var(--border);display:flex;align-items:center;justify-content:center;font-size:15px;flex-shrink:0;position:relative;z-index:1;transition:border-color .3s,background .3s}
.stage.pass .sico{border-color:var(--green);background:rgba(52,211,153,.08)}
.stage.fail .sico{border-color:var(--red);background:rgba(248,113,113,.08)}
.sbody{flex:1;padding-top:8px}
.sname{font-size:13px;font-weight:600;color:var(--text);margin-bottom:3px}
.stage.pending .sname{color:var(--muted)}
.sdet{font-size:12px;font-family:var(--mono);color:var(--muted);line-height:1.4}
.stage.pass .sdet{color:var(--green);opacity:.85}
.stage.fail .sdet{color:var(--red)}
.decision{border-radius:8px;padding:18px 22px;display:none}
.decision.show{display:block}
.decision.ok{background:rgba(52,211,153,.07);border:1px solid rgba(52,211,153,.25)}
.decision.no{background:rgba(248,113,113,.07);border:1px solid rgba(248,113,113,.25)}
.dhead{font-size:19px;font-weight:700;margin-bottom:6px}
.decision.ok .dhead{color:var(--green)}.decision.no .dhead{color:var(--red)}
.ddet{font-size:13px;color:var(--muted);line-height:1.5}
.proof{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;display:none}
.proof.show{display:block}
.plabel{font-size:11px;font-family:var(--mono);color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:12px}
.prow{display:flex;gap:12px;margin-bottom:7px;font-size:12px}
.pk{color:var(--muted);font-family:var(--mono);width:120px;flex-shrink:0}
.pv{color:var(--cyan);font-family:var(--mono);word-break:break-all}
.psigs{font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:10px;padding-top:10px;border-top:1px solid var(--border)}
.psigs b{color:var(--green)}
.idle{color:var(--muted);font-size:14px;text-align:center;padding:60px 0;font-family:var(--mono)}
footer{border-top:1px solid var(--border);padding:10px 32px;font-size:12px;color:var(--muted);display:flex;justify-content:space-between;flex-shrink:0}
footer a{color:var(--muted);text-decoration:none}
footer a:hover{color:var(--gold)}
@media(max-width:800px){.layout{grid-template-columns:1fr;overflow:auto}.left{border-right:none;border-bottom:1px solid var(--border)}}
</style>
</head>
<body>
<header>
  <div class="logo">Org<span>Forge</span></div>
  <div class="badge">Phase 0 \u00b7 Live Demo</div>
</header>
<div class="layout">
  <div class="left">
    <div>
      <div class="slabel">Scenarios</div>
      <div class="scenarios" id="scenarios"></div>
    </div>
    <div>
      <div class="slabel">Intent JSON</div>
      <textarea id="ij" spellcheck="false"></textarea>
    </div>
    <button class="btn" id="sbtn" onclick="run()">Evaluate Intent \u2192</button>
  </div>
  <div class="right">
    <div>
      <div class="ptitle">Authorization Pipeline \u2014 5 stages</div>
    </div>
    <div class="pipeline" id="pipeline"></div>
    <div class="decision" id="decision"></div>
    <div class="proof" id="proof"></div>
    <div class="idle" id="idle">Select a scenario or paste an intent JSON<br>and press Evaluate \u2192</div>
  </div>
</div>
<footer>
  <span>OrgForge \u2014 Cryptographic governance &nbsp;&middot;&nbsp; <a href="https://doi.org/10.5281/zenodo.18968718" target="_blank">Whitepaper</a></span>
  <span><a href="/api/orgspec" target="_blank">OrgSpec JSON</a> &nbsp;&middot;&nbsp; <a href="https://orgforge.io" target="_blank">orgforge.io</a></span>
</footer>
<script>
const SC=[
  {label:'Trade within limits',desc:'agent:trader_1 \u00b7 BUY ETH-USD \u00b7 $8,000',exp:'p',intent:{org_id:'org:demo',actor_id:'agent:trader_1',action_type:'PLACE_ORDER',params:{venue:'SIM_EXCHANGE',market:'ETH-USD',side:'BUY',type:'MARKET',notional_usd:8000}}},
  {label:'Order exceeds per-order limit',desc:'agent:trader_1 \u00b7 BUY ETH-USD \u00b7 $15,000',exp:'f',intent:{org_id:'org:demo',actor_id:'agent:trader_1',action_type:'PLACE_ORDER',params:{venue:'SIM_EXCHANGE',market:'ETH-USD',side:'BUY',type:'MARKET',notional_usd:15000}}},
  {label:'Tool call \u2014 approval required',desc:'agent:alpha \u00b7 TOOL_CALL \u00b7 code_exec (no approval)',exp:'f',intent:{org_id:'org:demo',actor_id:'agent:alpha',action_type:'TOOL_CALL',params:{tool:'code_exec',cost_units:10,payload_hash:'0xabc123'}}},
  {label:'Suspended actor blocked',desc:'agent:trader_suspended \u00b7 PLACE_ORDER',exp:'f',intent:{org_id:'org:demo',actor_id:'agent:trader_suspended',action_type:'PLACE_ORDER',params:{venue:'SIM_EXCHANGE',market:'ETH-USD',side:'SELL',type:'MARKET',notional_usd:1000}}}
];
const SMETA=[
  {stage:'validate',label:'Intent structure',icon:'\uD83D\uDD0E'},
  {stage:'actor',label:'Actor & role',icon:'\uD83E\uDEAA'},
  {stage:'freshness',label:'Intent freshness',icon:'\u23F1'},
  {stage:'policy',label:'Action policy',icon:'\uD83D\uDCCB'},
  {stage:'approval',label:'Approval gate',icon:'\u2705'}
];

const scEl=document.getElementById('scenarios');
SC.forEach((s,i)=>{
  const b=document.createElement('button');
  b.className='sc';
  b.innerHTML='<span class="sc-name">'+s.label+'<span class="tag '+s.exp+'">'+(s.exp==='p'?'AUTHORIZED':'REJECTED')+'</span></span><span class="sc-desc">'+s.desc+'</span>';
  b.onclick=()=>pick(i);
  scEl.appendChild(b);
});

function pick(i){
  document.querySelectorAll('.sc').forEach((b,j)=>b.classList.toggle('active',j===i));
  document.getElementById('ij').value=JSON.stringify({...SC[i].intent},null,2);
  reset();
}

function reset(){
  renderIdle();
  document.getElementById('decision').className='decision';
  document.getElementById('proof').className='proof';
  document.getElementById('idle').style.display='block';
}

function renderIdle(){
  document.getElementById('pipeline').innerHTML=SMETA.map(m=>'<div class="stage pending"><div class="sico">'+m.icon+'</div><div class="sbody"><div class="sname">'+m.label+'</div><div class="sdet">\u2014</div></div></div>').join('');
}

function renderStages(steps){
  const el=document.getElementById('pipeline');
  el.innerHTML='';
  let failed=false;
  SMETA.forEach(m=>{
    const s=steps.find(x=>x.stage===m.stage);
    let cls='pending',det='\u2014';
    if(s){cls=s.result==='pass'?'pass':'fail';det=s.detail;if(s.result==='fail')failed=true;}
    else if(failed){cls='pending';det='Not evaluated';}
    const d=document.createElement('div');
    d.className='stage '+cls;
    d.innerHTML='<div class="sico">'+m.icon+'</div><div class="sbody"><div class="sname">'+m.label+'</div><div class="sdet">'+det+'</div></div>';
    el.appendChild(d);
  });
}

async function run(){
  let intent;
  try{intent=JSON.parse(document.getElementById('ij').value);}catch(e){alert('Invalid JSON: '+e.message);return;}
  const btn=document.getElementById('sbtn');
  btn.disabled=true;btn.textContent='Evaluating\u2026';
  document.getElementById('idle').style.display='none';
  try{
    const r=await fetch('/api/evaluate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(intent)});
    const d=await r.json();
    renderStages(d.steps||[]);
    const dec=document.getElementById('decision');
    dec.className='decision show '+(d.authorized?'ok':'no');
    dec.innerHTML=d.authorized
      ?'<div class="dhead">\u2713 AUTHORIZED</div><div class="ddet">2-of-3 validator quorum reached. Authorization proof assembled and ready for execution layer.</div>'
      :'<div class="dhead">\u2717 REJECTED</div><div class="ddet">'+d.reason_code+': '+(d.detail||'')+'</div>';
    if(d.authorized&&d.proof){
      const p=d.proof;
      document.getElementById('proof').className='proof show';
      document.getElementById('proof').innerHTML='<div class="plabel">Authorization Proof \u2014 '+p.threshold+' quorum</div>'
        +'<div class="prow"><span class="pk">intent_hash</span><span class="pv">'+p.intent_hash+'</span></div>'
        +'<div class="prow"><span class="pk">org_id</span><span class="pv">'+p.org_id+'</span></div>'
        +'<div class="prow"><span class="pk">orgspec_version</span><span class="pv">'+p.orgspec_version+'</span></div>'
        +'<div class="prow"><span class="pk">issued_at</span><span class="pv">'+p.issued_at+' (unix)</span></div>'
        +'<div class="prow"><span class="pk">expires_at</span><span class="pv">'+p.expires_at+' (unix)</span></div>'
        +'<div class="psigs"><b>'+p.quorum_signatures[0].validator+'</b> '+p.quorum_signatures[0].sig.slice(0,34)+'\u2026<br><b>'+p.quorum_signatures[1].validator+'</b> '+p.quorum_signatures[1].sig.slice(0,34)+'\u2026</div>';
    }else{document.getElementById('proof').className='proof';}
  }catch(e){alert('API error: '+e.message);}
  finally{btn.disabled=false;btn.textContent='Evaluate Intent \u2192';}
}

renderIdle();pick(0);
</script>
</body>
</html>`;

// ─── Server ──────────────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const path = parsed.pathname;

  // CORS preflight
  if (req.method === 'OPTIONS') {
    send(res, 200, '', 'text/plain');
    return;
  }

  if (req.method === 'GET' && (path === '/' || path === '/demo')) {
    return send(res, 200, DEMO_HTML, 'text/html; charset=utf-8');
  }

  if (req.method === 'GET' && path === '/api/health') {
    return send(res, 200, { status: 'ok', version: 'phase-0', timestamp: Date.now() });
  }

  if (req.method === 'GET' && path === '/api/orgspec') {
    return send(res, 200, ORGSPEC);
  }

  if (req.method === 'POST' && path === '/api/evaluate') {
    let intent;
    try { intent = await parseBody(req); }
    catch (e) { return send(res, 400, { error: 'Invalid JSON body' }); }
    const result = assemble_proof(intent, ORGSPEC);
    return send(res, 200, result);
  }

  return send(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  console.log('\nOrgForge Demo API \u2014 Phase 0');
  console.log('http://localhost:' + PORT + '\n');
  console.log('Routes:');
  console.log('  GET  /               Demo UI');
  console.log('  POST /api/evaluate   Evaluate an intent');
  console.log('  GET  /api/orgspec    Current OrgSpec');
  console.log('  GET  /api/health     Health check\n');
});
