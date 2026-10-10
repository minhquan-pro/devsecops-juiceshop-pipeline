'use strict';
const $ = id => document.getElementById(id);
let csrf = '', knowledge = [];
function node(tag, text, cls) {
  const n = document.createElement(tag);
  n.textContent = text;
  if (cls) n.className = cls;
  return n;
}
function renderReport(report) {
  $('results').replaceChildren();
  const findings = report.findings || [];
  $('summary').textContent = `${findings.length} chỉ dấu cần thẩm định`;
  for (const item of findings) {
    const card = node('article', '');
    card.append(node('h3', item.title), node('span', item.rule_id, 'badge'),
      node('span', `${item.severity} / ${item.confidence}`, 'badge'));
    card.append(node('p', typeof item.evidence === 'object' ? JSON.stringify(item.evidence) : item.evidence));
    card.append(node('p', 'Khắc phục: ' + item.remediation));
    $('results').append(card);
  }
  if (!findings.length) $('results').append(node('p', 'Không có chỉ dấu theo bộ quy tắc hiện tại. Kết quả này không chứng minh ứng dụng an toàn.'));
  for (const err of report.errors || []) $('results').append(node('p', `${err.path}: ${err.type}`, 'error'));
}
async function submit(path, body, button) {
  button.disabled = true;
  $('status').textContent = 'Đang phân tích…';
  try {
    const response = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(body)});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Không thể phân tích');
    renderReport(result);
    $('status').textContent = 'Đã hoàn tất. Xem chỉ dấu, giới hạn và lỗi kết nối trước khi kết luận.';
  } catch(e) { $('status').textContent = e.message; }
  finally { button.disabled = false; }
}
function renderKnowledge() {
  const q = $('search').value.toLowerCase();
  $('knowledgeList').replaceChildren();
  for (const k of knowledge.filter(x => JSON.stringify(x).toLowerCase().includes(q))) {
    const card = node('article', '');
    card.append(node('h3', k.name), node('span', k.cwe, 'badge'), node('p', k.mechanism), node('p','Phòng ngừa: '+k.defense));
    const link = node('a', 'Tài liệu PortSwigger');
    link.href=k.url; link.target='_blank'; link.rel='noopener noreferrer';
    card.append(link); $('knowledgeList').append(card);
  }
}
document.querySelectorAll('nav button').forEach(button => button.addEventListener('click',()=>{
  document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('selected',b===button));
  ['scan','source','knowledge'].forEach(id=>$(id).hidden=id!==button.dataset.tab);
}));
$('scanBtn').addEventListener('click',()=>submit('/api/scan',{target:$('target').value,active:$('active').checked},$('scanBtn')));
$('sourceBtn').addEventListener('click',()=>submit('/api/source',{filename:$('filename').value,source:$('code').value},$('sourceBtn')));
$('search').addEventListener('input',renderKnowledge);
Promise.all([fetch('/api/session').then(r=>r.json()),fetch('/api/knowledge').then(r=>r.json())]).then(([session,data])=>{csrf=session.csrf;knowledge=data;renderKnowledge();}).catch(()=>{$('status').textContent='Không tải được phiên. Mở lại bằng địa chỉ 127.0.0.1.';});
