// ThreatLens — frontend helpers

// Auto-refresh admin page every 60s
if (window.location.pathname === '/admin') {
  setTimeout(() => window.location.reload(), 60000);
}

// Linkify bare CVE IDs in text nodes
document.querySelectorAll('.text-light, .text-muted').forEach(el => {
  if (el.children.length > 0) return;
  const html = el.innerHTML;
  const linked = html.replace(/(CVE-\d{4}-\d{4,})/g, '<a href="/cve/$1" style="color:var(--cyan);text-decoration:none;">$1</a>');
  if (linked !== html) el.innerHTML = linked;
});

// '/' focuses the search bar
document.addEventListener('keydown', e => {
  if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
    e.preventDefault();
    const s = document.querySelector('input[name="search"]');
    if (s) { s.focus(); s.select(); }
  }
});

// Bootstrap tooltips
document.querySelectorAll('[title]').forEach(el => {
  new bootstrap.Tooltip(el, { trigger: 'hover', placement: 'top' });
});
