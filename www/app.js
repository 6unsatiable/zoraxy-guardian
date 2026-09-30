(function () {
  const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));
  const esc = (s) => String(s ?? '').replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;');

  let cfg = null;
  const PAGE_SIZE = 50;
  let logState = { entries: [], total: 0, offset: 0, filter: '', source: '', sse: null };

  // ---------- theme ----------
  const THEME_KEY = 'guardian.theme';
  function applyTheme(t) {
    if (t === 'dark') document.documentElement.setAttribute('data-theme', 'dark');
    else document.documentElement.removeAttribute('data-theme');
  }
  applyTheme(localStorage.getItem(THEME_KEY) ||
    (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));

  $('#theme-toggle').addEventListener('click', () => {
    const cur = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    const next = cur === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    localStorage.setItem(THEME_KEY, next);
  });

  function setStatus(msg, isErr) {
    const el = $('#save-msg');
    el.textContent = msg || '';
    el.classList.toggle('err', !!isErr);
  }

  // Hosts list <-> comma-separated string
  const hostsToStr = (h) => Array.isArray(h) ? h.join(', ') : '';
  const strToHosts = (s) => {
    const out = String(s || '').split(',').map((x) => x.trim()).filter(Boolean);
    return out.length ? out : undefined;
  };

  function renderScopedTable(tableId, entries, opts) {
    opts = opts || {};
    const tbody = $('#' + tableId + ' tbody');
    tbody.innerHTML = '';
    (entries || []).forEach((entry, idx) => {
      const tr = document.createElement('tr');
      let extra = '';
      if (opts.exceptPaths) {
        extra = `<td><input type="text" data-idx="${idx}" data-field="except_paths" value="${esc(hostsToStr(entry.except_paths))}" placeholder="/robots.txt, /favicon.ico"></td>`;
      }
      tr.innerHTML = `
        <td><input type="text" data-idx="${idx}" data-field="value" value="${esc(entry.value)}"></td>
        <td><input type="text" data-idx="${idx}" data-field="hosts" value="${esc(hostsToStr(entry.hosts))}" placeholder="*"></td>
        ${extra}
        <td><button class="row-del" data-idx="${idx}" title="Delete">&times;</button></td>`;
      tbody.appendChild(tr);
    });
  }

  function readScopedTable(tableId) {
    const rows = $$('#' + tableId + ' tbody tr');
    const out = [];
    rows.forEach((tr) => {
      const value = tr.querySelector('[data-field="value"]').value.trim();
      const hosts = strToHosts(tr.querySelector('[data-field="hosts"]').value);
      const exceptEl = tr.querySelector('[data-field="except_paths"]');
      const except = exceptEl ? strToHosts(exceptEl.value) : undefined;
      if (!value) return;
      const entry = { value };
      if (hosts) entry.hosts = hosts;
      if (except) entry.except_paths = except;
      out.push(entry);
    });
    return out;
  }

  function renderWAF() {
    const tbody = $('#waf-table tbody');
    tbody.innerHTML = '';
    (cfg.waf_rules || []).forEach((rule, idx) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><input type="checkbox" data-idx="${idx}" data-field="enabled" ${rule.enabled ? 'checked' : ''}></td>
        <td><input type="text" data-idx="${idx}" data-field="name" value="${esc(rule.name)}"></td>
        <td><input type="text" data-idx="${idx}" data-field="pattern" value="${esc(rule.pattern)}"></td>
        <td><input type="text" data-idx="${idx}" data-field="hosts" value="${esc(hostsToStr(rule.hosts))}" placeholder="*"></td>
        <td><button class="row-del" data-idx="${idx}" title="Delete">&times;</button></td>`;
      tbody.appendChild(tr);
    });
  }

  function applyToUI(c) {
    cfg = c;
    renderScopedTable('ip-allow-table', c.ip_allowlist);
    renderScopedTable('ip-block-table', c.ip_blocklist);
    renderScopedTable('ua-table', c.ua_blocklist, { exceptPaths: true });
    renderScopedTable('hostblock-table', c.host_blocklist || []);
    renderWAF();
    $('#rate-enabled').checked = !!c.rate_limit?.enabled;
    $('#rate-rpm').value = c.rate_limit?.requests_per_minute ?? 600;
    $('#rate-burst').value = c.rate_limit?.burst ?? 200;
    $('#honeypot-enabled').checked = !!c.honeypot?.enabled;
    $('#honeypot-ban-secs').value = c.honeypot?.ban_seconds ?? 3600;
    renderScopedTable('honeypot-table', c.honeypot?.paths || []);
    $('#autoban-enabled').checked = !!c.auto_ban?.enabled;
    $('#autoban-threshold').value = c.auto_ban?.threshold ?? 5;
    $('#autoban-window').value = c.auto_ban?.window_seconds ?? 60;
    $('#autoban-ban-secs').value = c.auto_ban?.ban_seconds ?? 600;
    $('#fingerprint-enabled').checked = !!c.fingerprint_tracking?.enabled;
    $('#fingerprint-threshold').value = c.fingerprint_tracking?.threshold ?? 10;
    $('#fingerprint-window').value = c.fingerprint_tracking?.window_seconds ?? 300;
    $('#fingerprint-ban-secs').value = c.fingerprint_tracking?.ban_seconds ?? 3600;
    $('#trusted-proxy-cidrs').value = hostsToStr(c.trusted_proxy_cidrs);
    $('#trust-cloudflare').checked = !!c.trust_cloudflare;
    $('#exempt-cidrs').value = hostsToStr(c.exempt_cidrs);
    $('#ignore-zoraxy-blacklist').checked = !!c.ignore_zoraxy_blacklist;
  }

  function collectUI() {
    const wafRules = [];
    $$('#waf-table tbody tr').forEach((tr) => {
      const rule = {
        enabled: tr.querySelector('[data-field="enabled"]').checked,
        name: tr.querySelector('[data-field="name"]').value.trim(),
        pattern: tr.querySelector('[data-field="pattern"]').value,
        hosts: strToHosts(tr.querySelector('[data-field="hosts"]').value),
      };
      if (!rule.hosts) delete rule.hosts;
      if (rule.name || rule.pattern) wafRules.push(rule);
    });
    return {
      ip_allowlist: readScopedTable('ip-allow-table'),
      ip_blocklist: readScopedTable('ip-block-table'),
      ua_blocklist: readScopedTable('ua-table'),
      host_blocklist: readScopedTable('hostblock-table'),
      waf_rules: wafRules,
      rate_limit: {
        enabled: $('#rate-enabled').checked,
        requests_per_minute: parseInt($('#rate-rpm').value, 10) || 600,
        burst: parseInt($('#rate-burst').value, 10) || 200,
      },
      honeypot: {
        enabled: $('#honeypot-enabled').checked,
        ban_seconds: parseInt($('#honeypot-ban-secs').value, 10) || 3600,
        paths: readScopedTable('honeypot-table'),
      },
      auto_ban: {
        enabled: $('#autoban-enabled').checked,
        threshold: parseInt($('#autoban-threshold').value, 10) || 5,
        window_seconds: parseInt($('#autoban-window').value, 10) || 60,
        ban_seconds: parseInt($('#autoban-ban-secs').value, 10) || 600,
      },
      fingerprint_tracking: {
        enabled: $('#fingerprint-enabled').checked,
        threshold: parseInt($('#fingerprint-threshold').value, 10) || 10,
        window_seconds: parseInt($('#fingerprint-window').value, 10) || 300,
        ban_seconds: parseInt($('#fingerprint-ban-secs').value, 10) || 3600,
      },
      trusted_proxy_cidrs: strToHosts($('#trusted-proxy-cidrs').value) || [],
      trust_cloudflare: $('#trust-cloudflare').checked,
      exempt_cidrs: strToHosts($('#exempt-cidrs').value) || [],
      ignore_zoraxy_blacklist: $('#ignore-zoraxy-blacklist').checked,
    };
  }

  async function fetchConfig() {
    setStatus('Loading…');
    const r = await fetch('./api/config', { headers: { 'X-CSRF-Token': csrfToken } });
    if (!r.ok) { setStatus('Load failed', true); return; }
    applyToUI(await r.json());
    setStatus('Loaded');
  }

  async function saveConfig() {
    const body = collectUI();
    setStatus('Saving…');
    const r = await fetch('./api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      // The server explains validation failures (e.g. which rule has a bad regex).
      const detail = (await r.text().catch(() => '')).trim();
      setStatus('Save failed: ' + (detail || r.status), true);
      return;
    }
    // Reload what the server actually stored (defaults get filled in there).
    await fetchConfig();
    setStatus('Saved');
    fetchStatus();
  }

  // ---------- health banner ----------
  async function fetchStatus() {
    const r = await fetch('./api/status', { headers: { 'X-CSRF-Token': csrfToken } });
    if (!r.ok) return;
    const st = await r.json();
    const banner = $('#proxy-banner');
    const p = st.untrusted_proxy || {};
    if (p.count > 0 && !$('#trust-cloudflare').checked) {
      banner.textContent = `${p.count} request(s) since the plugin started came from a proxy address (last: ${p.last_ip} for ${p.last_host}), so Guardian could not see the real visitor. `
        + 'Those requests can still be blocked, but no bans or rate limits are applied to the proxy. Fix: General → "Trust Cloudflare", or add the proxy to Trusted proxy CIDRs.';
      banner.hidden = false;
    } else {
      banner.hidden = true;
    }
  }

  // ---------- block log: paginated + SSE-live ----------
  function renderLog() {
    const tbody = $('#log-table tbody');
    tbody.innerHTML = '';
    const filter = logState.filter.toLowerCase();
    const visible = filter ? logState.entries.filter((e) =>
      [e.ip, e.host, e.reason, e.user_agent, e.request_uri].some((v) => String(v || '').toLowerCase().includes(filter))
    ) : logState.entries;

    visible.forEach((e) => {
      const tr = document.createElement('tr');
      if (e.__fresh) { tr.classList.add('fresh-row'); delete e.__fresh; }
      const t = e.time ? new Date(e.time).toLocaleString() : '';
      const src = e.source || 'guardian';
      tr.innerHTML = `<td>${esc(t)}</td><td><span class="src src-${esc(src)}">${esc(src)}</span></td><td><code>${esc(e.ip)}</code></td><td>${esc(e.host)}</td><td>${esc(e.method)}</td><td><code>${esc(e.request_uri)}</code></td><td>${esc(e.user_agent)}</td><td><code>${esc(e.reason)}</code></td><td>${e.status || ''}</td>`;
      tbody.appendChild(tr);
    });
    $('#log-count').textContent = logState.total ? `(${visible.length}/${logState.total})` : '';
    $('#log-pager-info').textContent =
      logState.entries.length >= logState.total
        ? 'all loaded'
        : `showing ${logState.entries.length} of ${logState.total}`;
    $('#log-older').disabled = logState.entries.length >= logState.total;
  }

  async function fetchLogPage(append) {
    const offset = append ? logState.entries.length : 0;
    const src = logState.source ? `&source=${logState.source}` : '';
    const r = await fetch(`./api/blocklog?offset=${offset}&limit=${PAGE_SIZE}${src}`, {
      headers: { 'X-CSRF-Token': csrfToken },
    });
    if (!r.ok) return;
    const data = await r.json();
    logState.total = data.total;
    if (append) {
      logState.entries = logState.entries.concat(data.entries);
    } else {
      logState.entries = data.entries;
    }
    renderLog();
  }

  function formatCounts(items) {
    return (items || []).map((item) => `${item.value} (${item.count})`).join(' · ') || 'none';
  }

  async function fetchLogSummary() {
    const src = logState.source ? `?source=${logState.source}` : '';
    const r = await fetch(`./api/blocklog/summary${src}`, { headers: { 'X-CSRF-Token': csrfToken } });
    if (!r.ok) return;
    const data = await r.json();
    $('#log-summary').textContent = `Top IPs: ${formatCounts(data.top_ips)} | Top rules: ${formatCounts(data.top_reasons)}`;
  }

  async function exportBlockLog(format) {
    const src = logState.source ? `&source=${logState.source}` : '';
    const r = await fetch(`./api/blocklog/export?format=${format}${src}`, { headers: { 'X-CSRF-Token': csrfToken } });
    if (!r.ok) { setStatus('Log export failed: ' + r.status, true); return; }
    const url = URL.createObjectURL(await r.blob());
    const link = document.createElement('a');
    link.href = url;
    link.download = `guardian-block-log.${format}`;
    link.click();
    URL.revokeObjectURL(url);
  }

  function connectLogStream() {
    if (logState.sse) {
      logState.sse.close();
      logState.sse = null;
    }
    try {
      const es = new EventSource('./api/blocklog/stream');
      es.addEventListener('block', (ev) => {
        try {
          const entry = JSON.parse(ev.data);
          if (logState.source && (entry.source || 'guardian') !== logState.source) return;
          entry.__fresh = true;
          logState.entries.unshift(entry);
          // The server keeps the newest 2000; don't let a long-open tab grow forever.
          if (logState.entries.length > 2000) logState.entries.length = 2000;
          logState.total = Math.min(logState.total + 1, 2000);
          renderLog();
        } catch (_) { /* ignore */ }
      });
      es.onopen = () => $('#live').classList.add('on');
      es.onerror = () => {
        $('#live').classList.remove('on');
        // EventSource auto-reconnects; nothing to do.
      };
      logState.sse = es;
    } catch (_) {
      $('#live').classList.remove('on');
    }
  }

  // ---------- temp bans ----------
  async function fetchTempBans() {
    const r = await fetch('./api/tempbans', { headers: { 'X-CSRF-Token': csrfToken } });
    if (!r.ok) return;
    const bans = await r.json();
    const tbody = $('#tempbans-table tbody');
    tbody.innerHTML = '';
    bans.sort((a, b) => a.expires.localeCompare(b.expires));
    bans.forEach((b) => {
      const tr = document.createElement('tr');
      const exp = new Date(b.expires).toLocaleString();
      tr.innerHTML = `<td><code>${esc(b.ip)}</code></td><td>${esc(exp)}</td><td><button data-clear-ip="${esc(b.ip)}">Clear</button></td>`;
      tbody.appendChild(tr);
    });
    $('#tempbans-count').textContent = bans.length ? `(${bans.length})` : '';
  }

  async function clearTempBan(ip) {
    await fetch(`./api/tempbans/clear?ip=${encodeURIComponent(ip)}`, {
      method: 'POST',
      headers: { 'X-CSRF-Token': csrfToken },
    });
    fetchTempBans();
  }

  // ---------- fingerprint bans ----------
  async function fetchFingerprintBans() {
    const r = await fetch('./api/fingerprintbans', { headers: { 'X-CSRF-Token': csrfToken } });
    if (!r.ok) return;
    const bans = await r.json();
    const tbody = $('#fingerprintban-table tbody');
    tbody.innerHTML = '';
    bans.sort((a, b) => a.expires.localeCompare(b.expires));
    bans.forEach((b) => {
      const tr = document.createElement('tr');
      const exp = new Date(b.expires).toLocaleString();
      tr.innerHTML = `<td><code>${esc(b.fingerprint)}</code></td><td>${esc(exp)}</td><td><button data-clear-fp="${esc(b.fingerprint)}">Clear</button></td>`;
      tbody.appendChild(tr);
    });
  }

  async function clearFingerprintBan(fp) {
    await fetch(`./api/fingerprintbans/clear?fingerprint=${encodeURIComponent(fp)}`, {
      method: 'POST',
      headers: { 'X-CSRF-Token': csrfToken },
    });
    fetchFingerprintBans();
  }

  // ---------- wiring ----------
  $$('.tab').forEach((t) => t.addEventListener('click', () => {
    $$('.tab').forEach((x) => x.classList.remove('active'));
    $$('.tab-panel').forEach((x) => x.classList.remove('active'));
    t.classList.add('active');
    $('#tab-' + t.dataset.tab).classList.add('active');
    if (t.dataset.tab === 'log') { fetchLogPage(false); fetchLogSummary(); }
    if (t.dataset.tab === 'tempbans') fetchTempBans();
    if (t.dataset.tab === 'fingerprint') fetchFingerprintBans();
  }));

  document.body.addEventListener('click', (e) => {
    const add = e.target.dataset.add;
    if (add === 'ip-allow') { (cfg.ip_allowlist ||= []).push({ value: '' }); renderScopedTable('ip-allow-table', cfg.ip_allowlist); }
    else if (add === 'ip-block') { (cfg.ip_blocklist ||= []).push({ value: '' }); renderScopedTable('ip-block-table', cfg.ip_blocklist); }
    else if (add === 'ua') { (cfg.ua_blocklist ||= []).push({ value: '' }); renderScopedTable('ua-table', cfg.ua_blocklist, { exceptPaths: true }); }
    else if (add === 'hostblock') { (cfg.host_blocklist ||= []).push({ value: '' }); renderScopedTable('hostblock-table', cfg.host_blocklist); }
    else if (add === 'honeypot') {
      cfg.honeypot = cfg.honeypot || { enabled: false, ban_seconds: 3600, paths: [] };
      cfg.honeypot.paths = cfg.honeypot.paths || [];
      cfg.honeypot.paths.push({ value: '' });
      renderScopedTable('honeypot-table', cfg.honeypot.paths);
    }
    else if (e.target.dataset.clearIp) {
      clearTempBan(e.target.dataset.clearIp);
    }
    else if (e.target.dataset.clearFp) {
      clearFingerprintBan(e.target.dataset.clearFp);
    }
    else if (e.target.matches('.row-del')) {
      const table = e.target.closest('table');
      const tr = e.target.closest('tr');
      tr.remove();
      Array.from(table.querySelectorAll('tbody tr')).forEach((row, i) => {
        row.querySelectorAll('[data-idx]').forEach((el) => el.dataset.idx = i);
      });
    }
  });

  $('#waf-add').addEventListener('click', () => {
    cfg.waf_rules = cfg.waf_rules || [];
    cfg.waf_rules.push({ name: 'new-rule', pattern: '', enabled: true });
    renderWAF();
  });

  $('#save').addEventListener('click', saveConfig);
  $('#reload').addEventListener('click', fetchConfig);
  $('#log-refresh').addEventListener('click', () => fetchLogPage(false));
  $('#log-export-json').addEventListener('click', () => exportBlockLog('json'));
  $('#log-export-csv').addEventListener('click', () => exportBlockLog('csv'));
  $('#log-older').addEventListener('click', () => fetchLogPage(true));
  $('#log-filter').addEventListener('input', (e) => { logState.filter = e.target.value; renderLog(); });
  $('#log-source').addEventListener('change', (e) => { logState.source = e.target.value; fetchLogPage(false); fetchLogSummary(); });
  $('#tempbans-refresh').addEventListener('click', fetchTempBans);

  // ---------- Cloudflare import ----------
  async function importCF(apply) {
    const expression = $('#import-cf-input').value.trim();
    const msg = $('#import-cf-msg');
    msg.className = '';
    msg.textContent = '';
    if (!expression) {
      msg.textContent = 'paste an expression first';
      msg.className = 'err';
      return;
    }
    const r = await fetch('./api/import/cf', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
      body: JSON.stringify({ expression, apply }),
    });
    const data = await r.json();
    if (!r.ok) {
      msg.textContent = data.error || ('error ' + r.status);
      msg.className = 'err';
      return;
    }
    if (apply) {
      const s = data.applied || {};
      const total = (s.honeypot || 0) + (s.ua_blocklist || 0) + (s.host_blocklist || 0) + (s.waf_rules || 0) + (s.ip_blocklist || 0);
      msg.textContent = `applied: +${s.honeypot || 0} honeypot, +${s.ua_blocklist || 0} UA, +${s.host_blocklist || 0} host, +${s.waf_rules || 0} WAF, +${s.ip_blocklist || 0} IP (${total} new)`;
      msg.className = 'ok';
      $('#import-cf-preview-output').style.display = 'block';
      $('#import-cf-preview-pre').textContent = JSON.stringify(data, null, 2);
      // Refresh config view so the user sees the new rules.
      fetchConfig();
    } else {
      $('#import-cf-preview-output').style.display = 'block';
      $('#import-cf-preview-pre').textContent = JSON.stringify(data.preview, null, 2);
      const p = data.preview || {};
      msg.textContent = `preview: ${p.honeypot_paths?.length || 0} honeypot, ${p.ua_blocklist?.length || 0} UA, ${p.host_blocklist?.length || 0} host, ${p.waf_rules?.length || 0} WAF, ${p.ip_blocklist?.length || 0} IP, ${p.warnings?.length || 0} warnings`;
      msg.className = 'ok';
    }
  }
  $('#import-cf-preview').addEventListener('click', () => importCF(false));
  $('#import-cf-apply').addEventListener('click', () => importCF(true));

  async function updateRecommendedRules(apply) {
    const msg = $('#rules-update-msg');
    msg.className = '';
    msg.textContent = '';
    const r = await fetch('./api/rules/recommended', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
      body: JSON.stringify({ apply }),
    });
    const data = await r.json();
    if (!r.ok) {
      msg.textContent = data.error || ('error ' + r.status);
      msg.className = 'err';
      return;
    }
    const s = data.applied || data.preview || {};
    msg.textContent = `${apply ? 'merged' : 'preview'}: UA +${s.ua_added || 0}/−${s.ua_removed || 0}, WAF +${s.waf_added || 0}/−${s.waf_removed || 0}, honeypot +${s.honeypot_added || 0}/−${s.honeypot_removed || 0}`;
    msg.className = 'ok';
    if (apply) fetchConfig();
  }
  $('#rules-update-preview').addEventListener('click', () => updateRecommendedRules(false));
  $('#rules-update-apply').addEventListener('click', () => updateRecommendedRules(true));

  fetchConfig().then(fetchStatus);
  setInterval(fetchStatus, 60000);
  connectLogStream();
})();
