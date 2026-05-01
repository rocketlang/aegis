// AEGIS login page HTML — self-contained, no external assets
export function loginPage(error?: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AEGIS — Sign In</title>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  :root{--bg:#080810;--card:#0f1629;--border:#1e2d4a;--text:#e2e8f0;--muted:#64748b;--amber:#f59e0b;--red:#f87171;--green:#34d399}
  body{background:var(--bg);color:var(--text);font-family:'SF Mono',Consolas,'Courier New',monospace;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px}
  .shield{width:56px;height:56px;margin:0 auto 20px}
  .card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:40px;width:100%;max-width:380px}
  h1{font-size:22px;color:var(--amber);font-weight:700;text-align:center;margin-bottom:4px}
  .sub{color:var(--muted);font-size:12px;text-align:center;margin-bottom:28px;letter-spacing:.5px;text-transform:uppercase}
  label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);margin-bottom:6px}
  input{width:100%;background:#0a0e1a;border:1px solid var(--border);border-radius:6px;padding:10px 14px;color:var(--text);font-family:inherit;font-size:14px;outline:none;transition:border-color .15s}
  input:focus{border-color:var(--amber)}
  .field{margin-bottom:18px}
  .btn{width:100%;background:var(--amber);color:#000;border:none;border-radius:6px;padding:11px;font-family:inherit;font-size:14px;font-weight:700;cursor:pointer;transition:opacity .15s;margin-top:8px}
  .btn:hover{opacity:.85}
  .err{background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.3);border-radius:6px;padding:10px 14px;color:var(--red);font-size:13px;margin-bottom:18px;text-align:center}
  .footer{margin-top:24px;color:var(--muted);font-size:11px;text-align:center;letter-spacing:.3px}
  .dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--green);margin-right:6px;vertical-align:middle}
</style>
</head>
<body>
<div class="card">
  <svg class="shield" viewBox="0 0 56 56" fill="none" xmlns="http://www.w3.org/2000/svg">
    <rect width="56" height="56" rx="10" fill="#0f1629"/>
    <path d="M28 7L45 13.5V26C45 36.5 37.5 45.5 28 48C18.5 45.5 11 36.5 11 26V13.5Z" fill="#f59e0b"/>
    <text x="28" y="33" font-family="system-ui,sans-serif" font-size="18" font-weight="800" text-anchor="middle" fill="#0f1629">A</text>
  </svg>
  <h1>AEGIS</h1>
  <div class="sub">Agentic Governance Stack</div>
  ${error ? `<div class="err">${error}</div>` : ""}
  <form method="POST" action="/login">
    <div class="field">
      <label for="u">Username</label>
      <input id="u" name="username" type="text" autocomplete="username" autofocus required>
    </div>
    <div class="field">
      <label for="p">Password</label>
      <input id="p" name="password" type="password" autocomplete="current-password" required>
    </div>
    <button class="btn" type="submit">Sign In</button>
  </form>
</div>
<div class="footer"><span class="dot"></span>aegis.xshieldai.com · KavachOS Runtime</div>
</body>
</html>`;
}
