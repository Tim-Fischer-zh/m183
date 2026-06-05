'use strict';

// Serverseitiges HTML-Rendering (zwei Seiten: Login + Panel). Schlicht
// gehalten. Dynamische, aus dem Token stammende Werte werden escaped —
// sonst hätten wir neben der Algorithm Confusion noch ein XSS.

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function layout(title, body) {
  return `<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(title)}</title>
<style>
  :root{--bg:#f3f4f6;--panel:#fff;--ink:#1f2937;--muted:#6b7280;--line:#e5e7eb;--blue:#1f4e79;--red:#b91c1c;--red-bg:#fef2f2}
  *{box-sizing:border-box}
  body{margin:0;font-family:"Segoe UI",system-ui,-apple-system,Arial,sans-serif;background:var(--bg);color:var(--ink)}
  .top{background:var(--blue);color:#fff;padding:.9rem 1.3rem;font-weight:600;letter-spacing:.01em}
  .wrap{max-width:760px;margin:2rem auto;padding:0 1rem}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:1.6rem 1.8rem;box-shadow:0 1px 3px rgba(0,0,0,.05)}
  h1{font-size:1.4rem;margin:0 0 .3rem;color:var(--blue)}
  h2{font-size:1.1rem;margin:1.4rem 0 .6rem}
  p{line-height:1.5}
  label{display:block;font-size:.85rem;color:var(--muted);margin:.8rem 0 .25rem}
  input{width:100%;padding:.6rem .7rem;border:1px solid var(--line);border-radius:6px;font-size:1rem}
  button{margin-top:1.2rem;background:var(--blue);color:#fff;border:none;border-radius:6px;padding:.65rem 1.1rem;font-size:1rem;cursor:pointer}
  .muted{color:var(--muted);font-size:.9rem}
  .err{background:var(--red-bg);color:var(--red);border:1px solid #fca5a5;border-radius:6px;padding:.6rem .8rem;font-size:.9rem;margin-top:1rem}
  .badge{display:inline-block;font-size:.75rem;padding:.15rem .55rem;border-radius:999px;background:#e0e7ff;color:#3730a3;font-weight:600}
  .badge.admin{background:#fee2e2;color:#991b1b}
  table{width:100%;border-collapse:collapse;margin-top:.5rem;font-size:.95rem}
  th,td{text-align:left;padding:.5rem .6rem;border-bottom:1px solid var(--line)}
  th{color:var(--muted);font-weight:600}
  .confidential{background:var(--red-bg);border:1px solid #fca5a5;border-radius:6px;padding:.6rem .8rem;color:var(--red);font-size:.9rem;margin-top:1rem}
  dl{margin:0}dt{color:var(--muted);font-size:.8rem;margin-top:.7rem}dd{margin:.1rem 0 0;font-size:1.05rem}
  .foot{margin-top:1.4rem;padding-top:1rem;border-top:1px solid var(--line);font-size:.85rem;color:var(--muted);display:flex;justify-content:space-between;align-items:center}
  a{color:var(--blue)}
</style>
</head>
<body>
  <div class="top">Firmenportal</div>
  <div class="wrap">${body}</div>
</body>
</html>`;
}

function foot(p) {
  const who = esc(p.email || p.sub);
  return `<div class="foot"><span>Angemeldet als ${who} &middot; Rolle: ${esc(p.role)}</span><a href="/logout">Abmelden</a></div>`;
}

function renderLogin(error) {
  return layout('Login — Firmenportal', `
    <div class="card">
      <h1>Anmelden</h1>
      <p class="muted">Internes Mitarbeiter-Portal. Bitte mit deinen Zugangsdaten anmelden.</p>
      ${error ? `<div class="err">${esc(error)}</div>` : ''}
      <form method="POST" action="/login">
        <label for="email">E-Mail</label>
        <input id="email" name="email" type="email" autocomplete="username" value="anna@firma.ch">
        <label for="password">Passwort</label>
        <input id="password" name="password" type="password" autocomplete="current-password" value="passwort123">
        <button type="submit">Anmelden</button>
      </form>
    </div>`);
}

function renderUserPanel(p) {
  return layout('Mein Bereich — Firmenportal', `
    <div class="card">
      <h1>Mein Bereich</h1>
      <span class="badge">Rolle: ${esc(p.role)}</span>
      <h2>Meine Daten</h2>
      <dl>
        <dt>Name</dt><dd>${esc(p.name) || '&mdash;'}</dd>
        <dt>E-Mail</dt><dd>${esc(p.email || p.sub) || '&mdash;'}</dd>
        <dt>Rolle</dt><dd>${esc(p.role)}</dd>
      </dl>
      <p class="muted" style="margin-top:1.2rem">Der Admin-Bereich ist nur für Administratoren sichtbar.</p>
      ${foot(p)}
    </div>`);
}

function renderAdminPanel(p, employees) {
  const rows = employees.map((e) =>
    `<tr><td>${esc(e.name)}</td><td>${esc(e.email)}</td><td>${esc(e.role)}</td><td>CHF ${Number(e.salary).toLocaleString('de-CH')}</td></tr>`
  ).join('');
  return layout('Admin-Bereich — Firmenportal', `
    <div class="card">
      <h1>Admin-Bereich</h1>
      <span class="badge admin">Rolle: ${esc(p.role)}</span>
      <div class="confidential"><strong>Vertraulich.</strong> Nur für Administratoren bestimmt.</div>
      <h2>Alle Mitarbeitenden — Gehaltsliste</h2>
      <table>
        <thead><tr><th>Name</th><th>E-Mail</th><th>Funktion</th><th>Jahresgehalt</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      ${foot(p)}
    </div>`);
}

module.exports = { renderLogin, renderUserPanel, renderAdminPanel };
