/* CTFScanner 前端脚本：任务状态轮询、日志尾部加载、POC 管理、任务创建。 */

async function pollTask(id) {
  const box = document.getElementById("log-box");
  const badge = document.getElementById("st-badge");
  const stage = document.getElementById("st-stage");
  const prog = document.getElementById("st-progress");
  for (;;) {
    try {
      const r = await fetch(`/api/tasks/${id}/status`);
      if (r.ok) {
        const j = await r.json();
        if (badge) badge.textContent = j.status;
        if (stage) stage.textContent = j.current_stage;
        if (prog) prog.textContent = j.progress + "%";
        if (box && j.log_tail) box.textContent = j.log_tail.join("\n");
        if (j.status !== "running" && j.status !== "pending") {
          setTimeout(() => location.reload(), 1500);
          return;
        }
      }
    } catch (e) { /* 忽略瞬时网络错误 */ }
    await new Promise(res => setTimeout(res, 2000));
  }
}

async function loadLog(id) {
  const box = document.getElementById("log-box");
  if (!box) return;
  try {
    const r = await fetch(`/api/tasks/${id}/status`);
    if (r.ok) {
      const j = await r.json();
      box.textContent = (j.log_tail || []).join("\n") || "（空）";
    }
  } catch (e) { box.textContent = "加载失败"; }
}

/* 任务详情页签切换 */
function initTabs() {
  const tabs = [...document.querySelectorAll(".tab[data-tab]")];
  tabs.forEach(t => t.addEventListener("click", () => {
    tabs.forEach(x => x.classList.remove("active"));
    document.querySelectorAll(".tabpane").forEach(p => p.classList.remove("active"));
    t.classList.add("active");
    const pane = document.getElementById("pane-" + t.dataset.tab);
    if (pane) pane.classList.add("active");
  }));
}

/* 潜在漏洞：按级别快速筛选（详情页 / 漏洞页共用） */
function initSevFilter() {
  document.querySelectorAll("a[data-sev]").forEach(a => {
    a.addEventListener("click", ev => {
      ev.preventDefault();
      const sev = a.dataset.sev;
      document.querySelectorAll("tr[data-sev]").forEach(tr => {
        tr.style.display = (!sev || tr.dataset.sev === sev) ? "" : "none";
      });
    });
  });
}

/* 通用表格筛选：<input data-filter="#tbl-x"> 按整行文本做前端包含匹配 */
function initFilters() {
  document.querySelectorAll("input[data-filter]").forEach(inp => {
    if (inp.dataset.bound) return;   // 防止模板内显式调用与 DOMContentLoaded 重复绑定
    inp.dataset.bound = "1";
    const tbl = document.querySelector(inp.dataset.filter);
    if (!tbl) return;
    inp.addEventListener("input", () => {
      const q = inp.value.trim().toLowerCase();
      tbl.querySelectorAll("tbody tr").forEach(tr => {
        tr.style.display = (!q || tr.textContent.toLowerCase().includes(q)) ? "" : "none";
      });
    });
  });
  // 「只看已启用」勾选：与关键字过滤叠加（两者都满足才显示）
  document.querySelectorAll("input[data-filter-enabled]").forEach(chk => {
    if (chk.dataset.bound) return;
    chk.dataset.bound = "1";
    const tbl = document.querySelector(chk.dataset.filterEnabled);
    if (!tbl) return;
    chk.addEventListener("change", () => {
      tbl.querySelectorAll("tbody tr").forEach(tr => {
        tr.style.display = (!chk.checked || tr.dataset.enabled === "1") ? "" : "none";
      });
    });
  });
}

/* ---------- 任务列表：多条件筛选 + 行内操作 + 批量操作 ---------- */

function selectedTaskIds() {
  return [...document.querySelectorAll(".pick-row:checked")].map(c => Number(c.value));
}

/* 单个任务操作（停止 / 重启 / 删除）；msgEl 用于展示结果，任务列表与详情页共用 */
async function taskOp(action, id, btn, msgEl) {
  const say = t => { if (msgEl) msgEl.textContent = t; };
  if (action === "delete" && !confirm(`确认删除任务 #${id} 及其全部资产？`)) return;
  if (btn) btn.disabled = true;
  try {
    const r = await fetch(`/api/tasks/${id}/${action}`, { method: "POST" });
    const j = await r.json();
    if (j.msg) say(j.msg);
    if (j.error && !j.ok) {
      say(j.error);
      if (btn) btn.disabled = false;
      return;
    }
    setTimeout(() => location.reload(), 700);
  } catch (e) {
    say("网络错误");
    if (btn) btn.disabled = false;
  }
}

/* 绑定容器内的 [data-op] 按钮 */
function bindTaskOps(scope, msgEl) {
  document.querySelectorAll(`${scope} button[data-op]`).forEach(b => {
    // 去重：DOMContentLoaded 与任务详情模板内联脚本都会绑一次，重复绑定会让
    // "停止/重启/删除"各发两次 POST（删除还会弹两次确认，第二次 404）。
    // 先绑定的那个生效（内联脚本先执行、带 msgEl，所以操作反馈仍能显示）。
    if (b.dataset.opBound) return;
    b.dataset.opBound = "1";
    b.addEventListener("click", () => taskOp(b.dataset.op, b.dataset.id, b, msgEl));
  });
}

function initTaskTable() {
  const rows = [...document.querySelectorAll("#task-rows tr[data-id]")];
  if (!rows.length) return;

  // 1) 多条件筛选（各条件 AND）
  const inputs = [...document.querySelectorAll("[data-tfilter]")];
  const applyFilters = () => {
    const crit = {};
    inputs.forEach(i => { crit[i.dataset.tfilter] = i.value.trim().toLowerCase(); });
    rows.forEach(tr => {
      const ok = Object.entries(crit).every(([k, v]) => {
        if (!v) return true;
        const field = k === "stages" ? tr.dataset.stages : tr.dataset[k];
        return String(field || "").toLowerCase().includes(v);
      });
      tr.style.display = ok ? "" : "none";
    });
  };
  inputs.forEach(i => i.addEventListener("input", applyFilters));
  inputs.forEach(i => i.addEventListener("change", applyFilters));

  // 2) 勾选
  const pickAll = document.getElementById("pick-all");
  if (pickAll) {
    pickAll.addEventListener("change", () => {
      document.querySelectorAll(".pick-row").forEach(c => { c.checked = pickAll.checked; });
    });
  }

  // 3) 批量操作
  const bulkMsg = document.getElementById("bulk-msg");
  const bulk = async action => {
    const ids = selectedTaskIds();
    if (!ids.length) { bulkMsg.textContent = "请先勾选任务"; return; }
    if (action === "delete" && !confirm(`确认删除选中的 ${ids.length} 个任务及其全部资产？`)) return;
    bulkMsg.textContent = "提交中…";
    try {
      const r = await fetch("/api/tasks/bulk", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, ids }),
      });
      const j = await r.json();
      bulkMsg.textContent = j.error ? j.error
        : `已处理 ${j.affected} 个${j.skipped && j.skipped.length ? `，跳过 ${j.skipped.length} 个（状态不符）` : ""}`;
      setTimeout(() => location.reload(), 700);
    } catch (e) { bulkMsg.textContent = "网络错误"; }
  };
  document.querySelectorAll("[data-bulk]").forEach(b =>
    b.addEventListener("click", () => bulk(b.dataset.bulk)));

  // 4) 行内操作（查看/导出是链接；停止/重启/删除走 API）
  bindTaskOps("#task-rows", bulkMsg);

  // 5) 轮询未完成任务的状态
  const tick = async () => {
    await Promise.all(rows.map(async tr => {
      const id = tr.dataset.id;
      try {
        const r = await fetch(`/api/tasks/${id}/status`);
        if (!r.ok) return;
        const j = await r.json();
        tr.dataset.status = j.status;
        const badge = tr.querySelector(".badge");
        if (badge) { badge.textContent = j.status; badge.className = "badge st-" + j.status; }
        const prog = tr.querySelector(".progress");
        if (prog) {
          prog.innerHTML =
            `<div class="bar"><i style="width:${j.progress}%"></i></div>${j.progress}%`;
        }
        const stopBtn = tr.querySelector('button[data-op="stop"]');
        const restartBtn = tr.querySelector('button[data-op="restart"]');
        if (stopBtn) stopBtn.disabled = j.status !== "running";
        if (restartBtn) restartBtn.disabled = j.status === "running";
      } catch (e) { /* 忽略瞬时错误 */ }
    }));
    setTimeout(tick, 2500);
  };
  tick();
}

/* ---------- 策略配置页：面板折叠（默认折叠，展开状态存 localStorage） ---------- */

function initCollapsiblePanels() {
  const panels = [...document.querySelectorAll(".panel.collapsible")];
  if (!panels.length) return;
  const KEY = "ctfscanner.panels";
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem(KEY) || "{}") || {}; } catch (e) { saved = {}; }
  const persist = () => {
    const state = {};
    panels.forEach((p, i) => { state[p.dataset.panel || String(i)] = p.classList.contains("open"); });
    try { localStorage.setItem(KEY, JSON.stringify(state)); } catch (e) { /* 隐私模式：忽略 */ }
  };
  const setters = [];
  panels.forEach((p, i) => {
    const head = p.querySelector("h2");
    if (!head) return;                       // 无标题的面板不参与折叠
    const key = p.dataset.panel || String(i);
    head.classList.add("panel-head");
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "panel-toggle";
    head.appendChild(btn);
    const set = open => {
      p.classList.toggle("open", open);
      btn.textContent = open ? "折叠" : "展开";
      btn.setAttribute("aria-expanded", open ? "true" : "false");
    };
    set(saved[key] === true);                // 默认折叠：只有显式存过 true 才展开
    const flip = () => { set(!p.classList.contains("open")); persist(); };
    btn.addEventListener("click", ev => { ev.stopPropagation(); flip(); });
    head.addEventListener("click", flip);
    setters.push(set);
  });
  document.querySelectorAll("[data-panels]").forEach(b =>
    b.addEventListener("click", () => {
      const open = b.dataset.panels === "expand";
      setters.forEach(s => s(open));
      persist();
    }));
}

/* ---------- 资产页：表头复选框全选本页行 ---------- */

function initPickAll() {
  document.querySelectorAll("input[data-pick-all]").forEach(master => {
    if (master.dataset.bound) return;
    master.dataset.bound = "1";
    const tbl = document.querySelector(master.dataset.pickAll);
    if (!tbl) return;
    master.addEventListener("change", () => {
      tbl.querySelectorAll(".pick-row").forEach(c => { c.checked = master.checked; });
    });
  });
}

/* ---------- 主题切换：写 html[data-theme]，localStorage 记忆 ---------- */

function initTheme() {
  const sel = document.getElementById("theme-select");
  const KEY = "ctfscanner.theme";
  let saved = "dark";
  try { saved = localStorage.getItem(KEY) || "dark"; } catch (e) { /* 隐私模式 */ }
  const apply = t => {
    document.documentElement.setAttribute("data-theme", t);
    if (sel) sel.value = t;
    try { localStorage.setItem(KEY, t); } catch (e) { /* 忽略 */ }
  };
  apply(saved);
  if (sel) sel.addEventListener("change", () => apply(sel.value));
}

/* ---------- 漏洞人工复核（P1-1）：行内打标 + 勾选批量打标 ---------- */

async function postReview(ids, state, note) {
  const r = await fetch("/api/vulns/review", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ids, state, note: note || "" }),
  });
  return r.json();
}

function initVulnReview() {
  // 行内下拉：<select class="rv" data-review-id="12">（三态：待复核 / 确认存在 / 误报）
  document.querySelectorAll("select.rv[data-review-id]").forEach(sel => {
    if (sel.dataset.bound) return;
    sel.dataset.bound = "1";
    // 记住原值：POST 失败要能还原，否则界面会显示一个库里并不存在的状态
    const back = sel.value;
    sel.addEventListener("change", async () => {
      const state = sel.value;
      // 判误报要理由（报告附录会带出来），确认存在不强制；备注可留空、可取消
      let note = "";
      if (state === "false_positive") {
        const ans = prompt("判误报的理由（可留空，进报告备注）", "");
        if (ans === null) { sel.value = back; return; }
        note = ans;
      }
      sel.disabled = true;
      try {
        const j = await postReview([sel.dataset.reviewId], state, note);
        if (j.ok) { location.reload(); return; }
        alert(j.error || "操作失败");
      } catch (e) { alert("网络错误"); }
      sel.disabled = false;
      sel.value = back;
    });
  });

  // 批量：按钮 [data-review-bulk] 作用于本页所有勾选行（.pick-row:checked）
  document.querySelectorAll("button[data-review-bulk]").forEach(btn => {
    if (btn.dataset.bound) return;
    btn.dataset.bound = "1";
    btn.addEventListener("click", async () => {
      const state = btn.dataset.reviewBulk;
      const ids = [...document.querySelectorAll(".pick-row:checked")]
        .map(c => c.dataset.vid || c.value).filter(Boolean);
      const msg = document.querySelector("[data-review-msg]");
      if (!ids.length) { if (msg) msg.textContent = "请先勾选要打标的漏洞"; return; }
      let note = "";
      if (state === "false_positive") {
        const ans = prompt(`将 ${ids.length} 条标记为误报，理由（可留空）`, "");
        if (ans === null) return;
        note = ans;
      }
      btn.disabled = true;
      try {
        const j = await postReview(ids, state, note);
        if (j.ok) { location.reload(); return; }
        if (msg) msg.textContent = j.error || "操作失败";
      } catch (e) { if (msg) msg.textContent = "网络错误"; }
      btn.disabled = false;
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initTabs();
  initFilters();
  initCollapsiblePanels();
  initPickAll();
  initVulnReview();
  // 任务列表页的轮询/筛选/批量操作由 initTaskTable() 负责（模板内显式调用）
  // 任务详情页工具栏的操作按钮
  bindTaskOps(".toolbar");

  // 新建任务
  const tf = document.getElementById("task-form");
  if (tf) {
    tf.addEventListener("submit", async ev => {
      ev.preventDefault();
      const msg = document.getElementById("task-msg");
      msg.textContent = "提交中…";
      try {
        const r = await fetch("/api/tasks", { method: "POST", body: new FormData(tf) });
        const j = await r.json();
        if (j.id) {
          // 勾了「全端口 / 全目录」却没勾对应阶段时，后端会自动补上并回传 auto_stages
          const extra = (j.auto_stages && j.auto_stages.length)
            ? "（已自动补上阶段：" + j.auto_stages.join("、") + "）" : "";
          msg.textContent = "任务 #" + j.id + " 已创建" + extra;
          setTimeout(() => location.reload(), 1200);
        } else {
          msg.textContent = j.error || "创建失败";
        }
      } catch (e) { msg.textContent = "网络错误"; }
    });
  }

  // POC 上传 / 刷新 / 启停
  const pf = document.getElementById("poc-form");
  if (pf) {
    pf.addEventListener("submit", async ev => {
      ev.preventDefault();
      const msg = document.getElementById("poc-msg");
      try {
        const r = await fetch("/api/pocs/upload", { method: "POST", body: new FormData(pf) });
        const j = await r.json();
        msg.textContent = j.ok ? ("已导入：" + j.id) : ("失败：" + (j.error || "未知"));
        if (j.ok) setTimeout(() => location.reload(), 800);
      } catch (e) { msg.textContent = "网络错误"; }
    });
    document.getElementById("poc-refresh").addEventListener("click", async () => {
      await fetch("/api/pocs/refresh", { method: "POST" });
      location.reload();
    });
  }
  document.querySelectorAll("button.toggle").forEach(b => {
    b.addEventListener("click", async () => {
      await fetch(`/api/pocs/${b.dataset.id}/toggle`, { method: "POST" });
      location.reload();
    });
  });

  // POC 按分类批量开关（312 个逐个点不现实）
  const bulkEnable = document.getElementById("poc-bulk-enable");
  if (bulkEnable) {
    const send = async action => {
      const msg = document.getElementById("poc-bulk-msg");
      const body = {
        action,
        source: document.getElementById("poc-bulk-source").value,
        severity: document.getElementById("poc-bulk-severity").value,
        confidence: (document.getElementById("poc-bulk-confidence") || {}).value || "",
        kind: document.getElementById("poc-bulk-diff").checked ? "diff" : "",
      };
      const tip = action === "enable" ? "启用" : "关闭";
      if (!confirm(`确认按当前筛选条件批量${tip} POC？`)) return;
      msg.textContent = "处理中…";
      try {
        const r = await fetch("/api/pocs/bulk", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        const j = await r.json();
        msg.textContent = j.error ? j.error : `${tip}完成，影响 ${j.affected} 个`;
        if (j.ok) setTimeout(() => location.reload(), 900);
      } catch (e) { msg.textContent = "网络错误"; }
    };
    bulkEnable.addEventListener("click", () => send("enable"));
    document.getElementById("poc-bulk-disable").addEventListener("click", () => send("disable"));
  }
});
