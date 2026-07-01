package api

var dashboardHTML = []byte(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VibeSec Dashboard</title>
  <style>
    :root { --bg:#0b1020; --panel:#121a2e; --border:#2a3555; --text:#e8edf8; --muted:#9aa8c7; --accent:#6ee7b7; }
    body { margin:0; font-family:system-ui,sans-serif; background:var(--bg); color:var(--text); }
    .wrap { max-width:1100px; margin:0 auto; padding:2rem 1.25rem; }
    h1 { margin:0 0 .25rem; }
    .muted { color:var(--muted); }
    .row { display:flex; gap:.75rem; flex-wrap:wrap; margin:1rem 0; }
    input, button { border-radius:8px; border:1px solid var(--border); background:#0f172a; color:var(--text); padding:.55rem .75rem; }
    button { background:#14532d; cursor:pointer; }
    table { width:100%; border-collapse:collapse; margin-top:1rem; }
    th, td { text-align:left; padding:.6rem; border-bottom:1px solid var(--border); font-size:.92rem; }
    .card { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:1rem; margin-top:1rem; }
    .pill { padding:.15rem .5rem; border-radius:999px; font-size:.75rem; text-transform:uppercase; }
    .completed { background:#14532d; }
    .pending { background:#713f12; }
    .failed { background:#7f1d1d; }
    .running { background:#1e3a8a; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>VibeSec Dashboard</h1>
    <p class="muted">Enterprise scan history and scheduling</p>
    <div class="card">
      <label>API key</label>
      <div class="row">
        <input id="apiKey" type="password" placeholder="vs_..." style="flex:1;min-width:240px">
        <button onclick="loadScans()">Load scans</button>
      </div>
      <div class="row">
        <input id="target" type="url" placeholder="https://example.com" style="flex:1;min-width:240px">
        <button onclick="enqueueScan()">Enqueue scan</button>
      </div>
    </div>
    <div class="card">
      <h2 style="margin-top:0">Recent scans</h2>
      <table>
        <thead><tr><th>ID</th><th>Target</th><th>Status</th><th>Risk</th><th>Findings</th><th>Created</th><th>Report</th></tr></thead>
        <tbody id="scanRows"></tbody>
      </table>
    </div>
  </div>
  <script>
    function headers() {
      const key = document.getElementById('apiKey').value.trim();
      return key ? { 'X-API-Key': key, 'Content-Type': 'application/json' } : { 'Content-Type': 'application/json' };
    }
    function statusClass(status) {
      return 'pill ' + (status || 'pending');
    }
    async function loadScans() {
      const res = await fetch('/api/v1/scans?limit=50', { headers: headers() });
      const data = await res.json();
      const tbody = document.getElementById('scanRows');
      tbody.innerHTML = '';
      if (!res.ok) { tbody.innerHTML = '<tr><td colspan="7">' + (data.error || 'failed') + '</td></tr>'; return; }
      for (const scan of (data.scans || [])) {
        const tr = document.createElement('tr');
        const report = scan.report_html ? '<a href="' + scan.report_html + '" target="_blank">HTML</a>' : '-';
        tr.innerHTML = '<td><code>' + scan.id + '</code></td><td>' + scan.target + '</td><td><span class="' + statusClass(scan.status) + '">' + scan.status + '</span></td><td>' + (scan.risk_level || '-') + '</td><td>' + scan.finding_count + '</td><td>' + scan.created_at + '</td><td>' + report + '</td>';
        tbody.appendChild(tr);
      }
    }
    async function enqueueScan() {
      const target = document.getElementById('target').value.trim();
      if (!target) return;
      const res = await fetch('/api/v1/scans', { method:'POST', headers: headers(), body: JSON.stringify({ target }) });
      const data = await res.json();
      if (!res.ok) { alert(data.error || 'failed'); return; }
      await loadScans();
    }
    loadScans();
  </script>
</body>
</html>`)
