package demoui

// Style is the stylesheet every page shares. Colours are custom
// properties, redefined for a dark colour scheme; every interactive
// element shows focus-visible.
const Style = `:root{--bg:#f6f8fa;--surface:#fff;--text:#1f2328;--muted:#57606a;--border:#d0d7de;--link:#0969da;
--btn-bg:#0969da;--btn-text:#fff;--focus:#0969da;--chip-bg:#eaeef2;--code-bg:#eaeef2;
--ok:#1a7f37;--ok-bg:#dafbe1;--bad:#cf222e;--bad-bg:#ffebe9;--warn:#9a6700;--warn-border:#9a6700;--warn-bg:#fff8c5;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--surface:#161b22;--text:#e6edf3;--muted:#9da7b3;--border:#3d444d;--link:#58a6ff;
--btn-bg:#1f6feb;--btn-text:#fff;--focus:#58a6ff;--chip-bg:#262c36;--code-bg:#262c36;
--ok:#3fb950;--ok-bg:#0f2a1a;--bad:#ff7b72;--bad-bg:#3a1418;--warn:#d29922;--warn-border:#d29922;--warn-bg:#2e2410}}
*{box-sizing:border-box}
:focus-visible{outline:3px solid var(--focus);outline-offset:2px}
.btn:hover{filter:brightness(1.1)}.btn.secondary:hover{background:var(--chip-bg)}
body{font-family:system-ui,sans-serif;max-width:48rem;margin:0 auto;padding:0 1rem 2rem;line-height:1.5;background:var(--bg);color:var(--text)}
a{color:var(--link)}h1{line-height:1.25}
table{border-collapse:collapse}th,td{text-align:left;padding:.3rem .75rem .3rem 0;vertical-align:top}
code{word-break:break-all;background:var(--code-bg);padding:0 .2em;border-radius:4px}
.ok{color:var(--ok)}.bad{color:var(--bad)}.note{color:var(--muted);font-size:.9em}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1rem 1.25rem;margin:1rem 0}
.warn{border-color:var(--warn-border);background:var(--warn-bg)}
.site{display:flex;align-items:center;gap:.75rem;padding:1rem 0;margin-bottom:.5rem;border-bottom:1px solid var(--border)}
.site .rp-icon{font-size:2rem;line-height:1}.site p{margin:0}.site .rp-name{font-weight:700;font-size:1.1rem}
.site .rp-sub{color:var(--muted);font-size:.9em}
.site-nav{margin-left:auto;font-size:.9em;display:flex;flex-wrap:wrap;justify-content:flex-end;gap:.25rem 1rem}.site-nav a{white-space:nowrap}
.site-nav a[aria-current=page]{color:var(--text);font-weight:700;text-decoration:none}
.site-nav .count{display:inline-block;min-width:1.4em;border-radius:999px;padding:0 .4em;background:var(--btn-bg);color:var(--btn-text);font-size:.85em;font-weight:700;text-align:center}
.site-multi{flex-wrap:wrap}.site-multi>div{flex:1 1 12rem;min-width:0}
@media (max-width:40rem){.site-multi .site-nav{flex-basis:100%;justify-content:flex-start;margin-left:0}}
.badge{display:inline-block;border-radius:999px;padding:.05rem .6rem;font-size:.85em;font-weight:600;border:1px solid var(--border);background:var(--chip-bg);color:var(--text)}
.badge.ok{background:var(--ok-bg);color:var(--ok);border-color:transparent}.badge.bad{background:var(--bad-bg);color:var(--bad);border-color:transparent}
.badge.warn{background:var(--warn-bg);color:var(--warn);border-color:transparent}
.chips{display:flex;flex-wrap:wrap;gap:.4rem;padding:0;margin:.5rem 0;list-style:none}
.chips li{background:var(--chip-bg);border-radius:999px;padding:.1rem .7rem;font-size:.9em}
.btn{display:inline-block;background:var(--btn-bg);color:var(--btn-text);border:1px solid var(--btn-bg);border-radius:8px;padding:.5rem 1rem;font:inherit;font-weight:600;text-decoration:none;cursor:pointer}
.btn.secondary{background:transparent;color:var(--link);border-color:var(--border)}
.btn.danger{background:var(--bad);border-color:var(--bad);color:#fff}.btn.secondary.danger{background:transparent;color:var(--bad);border-color:var(--bad)}
.btn:disabled{opacity:.55;cursor:not-allowed}
.scenarios{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,20rem),1fr));gap:1rem}
.scenario{display:flex;flex-direction:column;margin:0}.scenario h2{margin:.1rem 0;font-size:1.2rem}
.scenario .who{margin:.2rem 0}.scenario .shows{flex:1}.scenario .btn{align-self:flex-start}
.respond h2{margin-top:0;font-size:1.2rem}.options{display:flex;flex-direction:column;gap:1rem}
.option{border-top:1px solid var(--border);padding-top:.75rem}.option h3{margin:0 0 .5rem;font-size:1.05rem}
.option .actions{display:flex;flex-wrap:wrap;gap:.5rem;margin:.5rem 0}
.opt-qr{text-align:center}.opt-qr .qr{width:min(100%,296px);height:auto;background:#fff;padding:8px;border-radius:8px;border:1px solid var(--border)}
@media (hover:none) and (pointer:coarse){.opt-device{order:-1}}
.progress p{margin:.25rem 0}#live{font-weight:600}
.spinner{display:inline-block;width:1em;height:1em;vertical-align:-.15em;border:.18em solid var(--border);border-top-color:var(--link);border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.spinner{animation-duration:3s}}
details.cli summary{cursor:pointer;font-weight:600}
.verdict{display:flex;align-items:center;gap:1rem;border-radius:12px;padding:1rem 1.25rem;margin:1rem 0;border:2px solid}
.verdict.approved{background:var(--ok-bg);border-color:var(--ok)}.verdict.refused{background:var(--bad-bg);border-color:var(--bad)}
.verdict.caution{background:var(--warn-bg);border-color:var(--warn-border)}.verdict.neutral{background:var(--surface);border-color:var(--border)}
.verdict .mark{font-size:3rem;line-height:1;margin:0;font-weight:700}.verdict.approved .mark{color:var(--ok)}.verdict.refused .mark{color:var(--bad)}
.verdict.caution .mark{color:var(--warn)}.verdict.neutral .mark{color:var(--muted)}
.verdict h1{margin:0 0 .4rem;font-size:1.5rem}.verdict h1:focus{outline:none}.verdict h1:focus-visible{outline:3px solid var(--focus);outline-offset:4px}
.badges{display:flex;flex-wrap:wrap;gap:.4rem;margin:.25rem 0}
.person h2{margin-top:0;font-size:1.2rem}.person h3{font-size:1rem;margin:1rem 0 .4rem}
.person-body{display:flex;flex-wrap:wrap;gap:1rem;align-items:flex-start}
.portrait{width:9rem;max-width:100%;height:auto;border-radius:8px;border:1px solid var(--border)}
.claims{flex:0 1 auto}.claims th{color:var(--muted);font-weight:600;padding-right:1.5rem}
details.raw{margin-top:1rem}
@media (max-width:30rem){.verdict{gap:.75rem;padding:.75rem 1rem}.verdict .mark{font-size:2rem}.verdict h1{font-size:1.25rem}}
.asked{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,14rem),1fr));gap:0 1rem}
.asked .missing{background:var(--warn-bg);color:var(--text)}
details.raw summary{cursor:pointer;color:var(--muted)}details.raw td{word-break:break-all}
.actions{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;margin:1.25rem 0}.actions form{margin:0}
[hidden]{display:none!important}
.visually-hidden{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.choices{display:flex;flex-direction:column;gap:.6rem;border:0;padding:0;margin:1rem 0}.choices legend{font-weight:700;margin-bottom:.4rem;padding:0}
.choice{display:flex;gap:.75rem;align-items:flex-start;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:.75rem 1rem;cursor:pointer}
.choice:hover{border-color:var(--muted)}.choice:has(input:checked){border-color:var(--link);box-shadow:0 0 0 1px var(--link)}
.choice:has(input:disabled){opacity:.6;cursor:not-allowed}
.choice input{width:1.15rem;height:1.15rem;margin:.2rem 0 0;flex:none;accent-color:var(--btn-bg)}
.choice strong{display:block}.choice .note{display:block}
.lead{font-size:1.1rem}.card:not(.scenario) h2{margin-top:0;font-size:1.2rem}
.dropzone{position:relative;display:flex;flex-direction:column;align-items:center;gap:.2rem;text-align:center;padding:1.5rem 1rem;border:2px dashed var(--border);border-radius:12px;background:var(--bg);cursor:pointer}
.dropzone:hover,.dropzone.dragover{border-color:var(--link);background:var(--chip-bg)}
.dropzone:has(input:focus-visible){outline:3px solid var(--focus);outline-offset:2px}
.dropzone .icon{font-size:2.2rem;line-height:1}.dropzone .file-name{font-weight:600;word-break:break-all}
.dropzone input{position:absolute;inset:0;width:100%;height:100%;opacity:0;cursor:pointer}
details.reveal>summary{list-style:none;display:inline-block}details.reveal>summary::-webkit-details-marker{display:none}
details.reveal[open]>summary{display:none}
.code-display{font:700 2.2rem/1.2 ui-monospace,monospace;letter-spacing:.25em;margin:.25rem 0}
.code-field{--cell:2.6rem;display:inline-block;overflow:hidden;width:calc(6 * var(--cell) + 4px);border:2px solid var(--muted);border-radius:8px;background:var(--surface);vertical-align:middle}
.code-field:focus-within{outline:3px solid var(--focus);outline-offset:2px;border-color:var(--focus)}
.code-field input{display:block;width:calc(7 * var(--cell));margin:0;border:0;outline:none;padding:.35rem 0 .35rem calc((var(--cell) - 1ch) / 2);
font:700 1.75rem/1.3 ui-monospace,monospace;letter-spacing:calc(var(--cell) - 1ch);color:var(--text);
background:repeating-linear-gradient(90deg,transparent 0 calc(var(--cell) - 1px),var(--border) calc(var(--cell) - 1px) var(--cell))}
.code-label{display:block;font-weight:600;margin-bottom:.4rem}
.steps{list-style:none;padding:0;margin:.5rem 0;display:flex;flex-direction:column;gap:.4rem}
.steps li{display:flex;gap:.6rem;align-items:center;color:var(--muted)}
.steps li::before{content:"";display:inline-grid;place-items:center;flex:none;width:1.3rem;height:1.3rem;border-radius:50%;border:2px solid var(--border);font-size:.8rem;font-weight:700}
.steps li[data-state=done],.steps li[data-state=current],.steps li[data-state=failed]{color:var(--text)}
.steps li[data-state=done]::before{content:"✓";background:var(--ok);border-color:var(--ok);color:#fff}
.steps li[data-state=failed]::before{content:"✗";background:var(--bad);border-color:var(--bad);color:#fff}
.steps li[data-state=current]::before{border-top-color:var(--link);animation:spin 1s linear infinite}
@media (prefers-reduced-motion:reduce){.steps li[data-state=current]::before{animation-duration:3s}}
.entries{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,18rem),1fr));gap:1rem;padding:0;margin:1rem 0;list-style:none}
.entry{margin:0;display:flex;flex-direction:column;gap:.25rem}.entry .actions{margin:.5rem 0 0}
.facts{display:grid;grid-template-columns:auto 1fr;gap:.15rem .75rem;margin:.25rem 0}.facts dt{color:var(--muted)}.facts dd{margin:0}
details.confirm>summary{list-style:none;display:inline-block}details.confirm>summary::-webkit-details-marker{display:none}
details.confirm .when-open,details.confirm[open] .when-closed{display:none}details.confirm[open] .when-open{display:inline}details.confirm form{margin:.5rem 0 0}
.timeline{list-style:none;padding:0 0 0 1rem;margin:.5rem 0;border-left:2px solid var(--border)}
.timeline li{position:relative;padding:.2rem 0 .6rem .75rem}
.timeline li::before{content:"";position:absolute;left:calc(-1rem - 7px);top:.65rem;width:12px;height:12px;border-radius:50%;background:var(--link);border:2px solid var(--bg)}
.timeline time{color:var(--muted);font-size:.9em;margin-right:.5rem}
.empty{text-align:center;color:var(--muted);padding:1.5rem 1rem}
.progress-frame{width:100%;height:9rem;border:0}.progress-summary{font-weight:600;margin:.25rem 0}
.chips .chip{background:var(--chip-bg);border-radius:999px;padding:.1rem .7rem;font-size:.9em}
.fmt{display:inline-block;border-radius:999px;padding:0 .55rem;font-size:.85em;font-weight:600;border:1px solid var(--border);background:var(--chip-bg)}
.choice.block{display:block}.choice.block strong{display:inline}.choice.block>input{margin:0 .5rem 0 0;vertical-align:-.15em}
.choice-portrait{float:right;width:4.5rem;height:auto;margin:0 0 .5rem .75rem;border-radius:6px;border:1px solid var(--border)}
.choice-detail{display:block;margin-top:.5rem}.choice-detail .chips{margin:.3rem 0}.claim-paths{display:block}.claim-paths code{font-size:.85em}
input[type=text]{font:inherit;padding:.5rem .65rem;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--text)}
.paste-row{display:flex;gap:.5rem;margin:.25rem 0}.paste-row input{flex:1;min-width:0}
.entries.wide{grid-template-columns:repeat(auto-fill,minmax(min(100%,21rem),1fr))}
.wallet-card-head{display:flex;gap:1rem;align-items:center;margin-bottom:.5rem}.wallet-card-head p{margin:.1rem 0}
.wc-portrait{width:4.5rem;height:auto;border-radius:8px;border:1px solid var(--border)}.wc-name{font-weight:700;font-size:1.15rem}
.wallet-card .claims th{padding-right:1rem}
.decision .btn{min-width:8rem;text-align:center}
`
