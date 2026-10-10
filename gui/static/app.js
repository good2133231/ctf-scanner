/* CTFScanner 前端脚本：任务状态轮询、日志尾部加载、POC 管理、任务创建。 */

// 后台路径随机化（续138）：控制台挂在每次启动随机生成的两段前缀下。
// 模板里的链接走 url_for() 会自动带前缀，JS 里的**不会** —— 所以所有绝对 URL 都必须过 u()。
// 基路径由 base.html 的 <meta name="ctf-base"> 给出（值就是 Flask 的 request.script_root；
// 挂在根路径时它是空串 ⇒ 不启用随机路径时行为与改动前一字不差）。
const CTF_BASE = ((document.querySelector('meta[name="ctf-base"]') || {}).content || "").replace(/\/+$/, "");
function absUrl(p) { return CTF_BASE + p; }

async function pollTask(id) {
  const box = document.getElementById("log-box");
  const badge = document.getElementById("st-badge");
  const stage = document.getElementById("st-stage");
  const prog = document.getElementById("st-progress");
  for (;;) {
    try {
      const r = await fetch(absUrl(`/api/tasks/${id}/status`));
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
    const r = await fetch(absUrl(`/api/tasks/${id}/status`));
    if (r.ok) {
      const j = await r.json();
      box.textContent = (j.log_tail || []).join("\n") || "（空）";
    }
  } catch (e) { box.textContent = "加载失败"; }
}

/* 任务详情页签切换。认 URL 锚点（#sites / #dirs / …）：资产页签的翻页与筛选都是**整页刷新**，
   分页条与 GET 表单的链接/action 尾部都带锚点，这里据此回到原页签 —— 否则用户翻一页、
   查一次就掉回第一个页签（「潜在漏洞」），看起来像"翻页没生效"。
   锚点认不出来（或被删掉）时保持模板的默认页签，不报错。 */
function initTabs() {
  const tabs = [...document.querySelectorAll(".tab[data-tab]")];
  const show = t => {
    tabs.forEach(x => x.classList.remove("active"));
    document.querySelectorAll(".tabpane").forEach(p => p.classList.remove("active"));
    t.classList.add("active");
    const pane = document.getElementById("pane-" + t.dataset.tab);
    if (pane) pane.classList.add("active");
  };
  tabs.forEach(t => t.addEventListener("click", () => show(t)));
  const want = (location.hash || "").replace(/^#/, "");
  const hit = want && tabs.find(t => t.dataset.tab === want);
  if (hit) show(hit);
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
    const r = await fetch(absUrl(`/api/tasks/${id}/${action}`), { method: "POST" });
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

  // 1) 筛选已搬到**服务端**（续53）：`/tasks` 现在分页，前端筛选只会筛当前页 —— 比原来更误导。
  //    原来那段 `[data-tfilter]` 前端过滤已删除。⚠️ 上面的 `rows` 仍要保留：下面第 5 步
  //    轮询未完成任务状态时要用它（别顺手删掉）。

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
      const r = await fetch(absUrl("/api/tasks/bulk"), {
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
  //
  // 续93：改成**一次批量**请求。原先对每一行各发一次 `/api/tasks/<id>/status` —— 页大小 100
  // 时每 2.5 秒就是 100 个请求，而且每个响应里后端都要 `_tail()` **整份读一遍日志**
  // （列表页根本不显示日志，纯属白读）。现在一次问完，且**只问还没结束的行**；
  // 全页都跑完就停表，不再空转（原先是无限轮询，连 done/stopped 的行也一直问）。
  const TERMINAL = new Set(["done", "failed", "stopped"]);
  const ST_LABEL = { queued: "排队中" };   // 与模板首屏同口径（否则首轮轮询会把「排队中」冲成 queued）
  const liveRows = () => rows.filter(tr => !TERMINAL.has(tr.dataset.status));
  const tick = async () => {
    const live = liveRows();
    if (!live.length) return;                 // 本页没有在跑的任务：不轮询、也不刷新
    try {
      const ids = live.map(tr => tr.dataset.id).join(",");
      const r = await fetch(absUrl(`/api/tasks/status?ids=${ids}`));
      if (r.ok) {
        const map = (await r.json()).tasks || {};
        live.forEach(tr => {
          const st = map[tr.dataset.id];
          if (!st) return;
          tr.dataset.status = st.status;
          const badge = tr.querySelector(".badge");
          if (badge) {
            badge.textContent = ST_LABEL[st.status] || st.status;
            badge.className = "badge st-" + st.status;
          }
          const prog = tr.querySelector(".progress");
          if (prog) {
            prog.innerHTML =
              `<div class="bar"><i style="width:${st.progress}%"></i></div>${st.progress}%`;
          }
          const stopBtn = tr.querySelector('button[data-op="stop"]');
          const restartBtn = tr.querySelector('button[data-op="restart"]');
          if (stopBtn) stopBtn.disabled = st.status !== "running";
          if (restartBtn) restartBtn.disabled = st.status === "running";
        });
      }
    } catch (e) { /* 忽略瞬时错误 */ }
    if (!liveRows().length) {
      // 全跑完了：刷新一次，把「统计 / 运行时长」这些服务端渲染的静态列带出来
      // （与详情页 pollTask 收尾同口径）。但用户此刻若正把光标放在筛选框里，
      // 就别抢他的输入 —— 留给他手动刷新。
      if (!document.querySelector("input:focus, select:focus, textarea:focus")) {
        setTimeout(() => location.reload(), 1500);
      }
      return;
    }
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

/* 新建任务表单的"一键批量勾选"（续118）。

   判据只有一份，来自模板：`[data-ck-group]` 划定分组，`data-ck-default` 说明"页面刚打开时
   该不该勾"。JS **不认识任何阶段名** —— 阶段清单是 `runner.STAGE_ORDER` 在后端渲染出来的，
   在这里再抄一份就迟早和它漂移（本仓在 C 段判据、CDN 判据上都修过"同一规则写两处"的错）。
   按钮只做"改勾选状态"这一件事：不提交、不清目标、不碰登录态。 */
function initTaskCheckAll() {
  const tf = document.getElementById("task-form");
  if (!tf) return;
  tf.querySelectorAll("button[data-ck-mode]").forEach(btn => {
    if (btn.dataset.bound) return;      // 与 initFilters 同款防重复绑定
    btn.dataset.bound = "1";
    btn.addEventListener("click", () => {
      const mode = btn.dataset.ckMode;
      const scope = (btn.dataset.ckScope || "").split(",").filter(Boolean);
      let n = 0;
      scope.forEach(g => {
        tf.querySelectorAll(`[data-ck-group="${g}"] input[type=checkbox]`).forEach(c => {
          c.checked = mode === "all" ? true
            : mode === "none" ? false : c.dataset.ckDefault === "1";
          n++;
        });
      });
      const msg = document.getElementById("task-msg");
      const label = mode === "all" ? "全部勾上" : mode === "none" ? "全部清掉" : "恢复默认";
      if (msg) msg.textContent = n ? `已${label}（${n} 个选项）` : "没有找到可勾选的选项";
    });
  });
}


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

/* ---------- 站点表：批量在浏览器打开勾选站点 ---------- */
// 浏览器的弹窗拦截只认「用户手势」：必须在 click 处理器里**同步**逐个 window.open，
// 一旦塞进 setTimeout / await 之后就会被拦成"只开第一个"。所以这里不 await、不延迟。
// 上限 20 是防手滑（勾 200 个站点 = 200 个标签页，浏览器直接卡死），超出的部分如实报出来。
// 只开标签页、不发任何请求 —— 续145 起它是站点表上**唯一**的批量动作（四个补扫入口已摘掉）。
// 勾选行从哪张表读，由按钮自己的 `data-pick-from` 给出（任务详情＝#tbl-detail-sites、
// 跨任务站点页＝#tbl-all-sites）。这里**刻意不写死任何表 id**：写死就等于"只有那一页能用"，
// 别的页面接上来只会静默失灵（续145 之前它硬编码 #tbl-detail-sites，/sites 的全选因此没有用途）。
const OPEN_SITES_MAX = 20;

function initOpenSites() {
  const btn = document.getElementById("btn-open-sites");
  if (!btn || btn.dataset.bound) return;
  btn.dataset.bound = "1";
  btn.addEventListener("click", () => {
    const msg = document.getElementById("op-msg");
    const box = document.getElementById("op-list");
    const scope = btn.dataset.pickFrom;
    const urls = scope
      ? [...document.querySelectorAll(`${scope} .pick-row:checked`)].map(c => c.value).filter(Boolean)
      : [];
    if (box) box.innerHTML = "";
    // 接线漏了（模板忘了给 data-pick-from）就**说出来**，别静默变成"勾了没反应"
    if (!scope) {
      if (msg) msg.textContent = "「批量打开」没接上表格：按钮缺 data-pick-from";
      return;
    }
    if (!urls.length) { if (msg) msg.textContent = "请先勾选要打开的站点"; return; }
    const list = urls.slice(0, OPEN_SITES_MAX);
    const rest = list.slice(1);
    // 浏览器的硬策略：**一次用户手势只放行一个 window.open**，后面的同步调用直接拿到 null。
    // 旧实现把这一律记成"被弹窗拦截，请允许本站弹出窗口后重试"—— 但即便允许，第二个照样开不出来，
    // 用户看到的就是"批量打开只能开一个"。这里不跟策略硬碰：第一个直接开，**其余渲染成真实链接**
    //（点每个链接各自是一次手势，浏览器允许），并给一个"复制链接清单"给要批量粘进别处的人。
    let first = null;
    try { first = window.open(list[0], "_blank"); } catch (e) { first = null; }
    if (first) { try { first.opener = null; } catch (e) { /* 跨域句柄，忽略 */ } }
    if (box && rest.length) {
      const tip = document.createElement("div");
      tip.className = "muted small";
      tip.textContent = `剩下 ${rest.length} 个逐个点即可各开一个标签页（浏览器只允许一次点击开一个）：`;
      box.appendChild(tip);
      rest.forEach(u => {
        const a = document.createElement("a");
        a.href = u; a.target = "_blank"; a.rel = "noopener noreferrer";
        a.className = "op-link mono"; a.textContent = u;
        box.appendChild(a);
      });
      const cp = document.createElement("button");
      cp.type = "button"; cp.className = "ghost"; cp.textContent = "复制链接清单";
      cp.addEventListener("click", async () => {
        const text = list.join("\n");
        try {
          await navigator.clipboard.writeText(text);
          cp.textContent = "已复制 " + list.length + " 条";
        } catch (e) {
          // 非安全上下文（http://127.0.0.1 之外的裸 IP）里 clipboard 不可用 → 退回选中文本
          const ta = document.createElement("textarea");
          ta.value = text; document.body.appendChild(ta); ta.select();
          let ok = false;
          try { ok = document.execCommand("copy"); } catch (e2) { ok = false; }
          document.body.removeChild(ta);
          cp.textContent = ok ? "已复制 " + list.length + " 条" : "复制失败，请手动选取";
        }
      });
      box.appendChild(cp);
    }
    let text = first
      ? `已打开第 1 个${rest.length ? `，其余 ${rest.length} 个见下方链接` : ""}`
      : `第 1 个被弹窗拦截（请允许本站弹出窗口），${rest.length ? `其余 ${rest.length} 个见下方链接` : ""}`;
    if (urls.length > list.length) {
      text += `；另有 ${urls.length - list.length} 个未列出（单次上限 ${OPEN_SITES_MAX}）`;
    }
    if (msg) msg.textContent = text;
  });
}

/* ---------- 站点截图灯箱（点击缩略图放大，遮罩/关闭钮/Esc 关闭，不新开标签页） ---------- */
function initLightbox() {
  const overlay = document.getElementById("lb-overlay");
  const img = document.getElementById("lb-img");
  const close = document.getElementById("lb-close");
  if (!overlay || !img) return;
  const open = src => {
    img.src = src; overlay.classList.add("open"); overlay.setAttribute("aria-hidden", "false");
  };
  const shut = () => { overlay.classList.remove("open"); img.src = ""; overlay.setAttribute("aria-hidden", "true"); };
  // 事件委托：缩略图可能跨页/动态渲染，绑在 document 上更稳
  document.addEventListener("click", e => {
    const t = e.target.closest && e.target.closest(".shot-thumb");
    if (t && t.dataset.full) { e.preventDefault(); open(t.dataset.full); }
  });
  if (close) close.addEventListener("click", shut);
  overlay.addEventListener("click", e => { if (e.target === overlay) shut(); });
  document.addEventListener("keydown", e => { if (e.key === "Escape") shut(); });
}

/* ---------- 主题：默认档与存储键在 base.html 的首屏脚本里（那里必须早于首次绘制），这里只接线 ---------- */

function initTheme() {
  const sel = document.getElementById("theme-select");
  const KEY = window.CTF_THEME_KEY;
  const apply = t => {
    document.documentElement.setAttribute("data-theme", t);
    if (sel) sel.value = t;
    try { localStorage.setItem(KEY, t); } catch (e) { /* 隐私模式：本次会话内仍然切得动 */ }
  };
  apply(document.documentElement.getAttribute("data-theme") || window.CTF_THEME_DEFAULT);
  if (sel) sel.addEventListener("change", () => apply(sel.value));
}

/* ---------- 漏洞人工复核（P1-1）：行内打标 + 勾选批量打标 ---------- */

async function postReview(ids, state, note) {
  const r = await fetch(absUrl("/api/vulns/review"), {
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

  // 批量：按钮 [data-review-bulk] 只作用于**它所在那个面板**里的勾选行（续146，理由见下面那段）
  document.querySelectorAll("button[data-review-bulk]").forEach(btn => {
    if (btn.dataset.bound) return;
    btn.dataset.bound = "1";
    btn.addEventListener("click", async () => {
      const state = btn.dataset.reviewBulk;
      // 续146：只读**按钮所在那个面板**里的勾选。此前读的是整页 `.pick-row:checked`，
      // 于是在任务详情页勾了站点行、再切到漏洞页签点「批量确认存在」，会把**站点 URL** 当漏洞 id
      // 发出去（服务端按非法 id 忽略 ⇒ 现象只是"点了没反应"，最难查的那种静默失灵）。
      // 按**容器**收而不是按表 id 收：跨任务 /vulns 页的表叫 `#tbl-vulns-all`、任务详情页叫
      // `#tbl-vulns`，写死任何一个都会让另一页失灵 —— 与「批量打开」的 `data-pick-from` 同一个教训。
      const scope = btn.closest(".panel") || document;
      const ids = [...scope.querySelectorAll(".pick-row:checked")]
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
  initTaskCheckAll();
  initOpenSites();
  initVulnReview();
  initLightbox();
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
        const r = await fetch(absUrl("/api/tasks"), { method: "POST", body: new FormData(tf) });
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
        const r = await fetch(absUrl("/api/pocs/upload"), { method: "POST", body: new FormData(pf) });
        const j = await r.json();
        msg.textContent = j.ok ? ("已导入：" + j.id) : ("失败：" + (j.error || "未知"));
        if (j.ok) setTimeout(() => location.reload(), 800);
      } catch (e) { msg.textContent = "网络错误"; }
    });
    document.getElementById("poc-refresh").addEventListener("click", async () => {
      await fetch(absUrl("/api/pocs/refresh"), { method: "POST" });
      location.reload();
    });
  }
  document.querySelectorAll("button.toggle").forEach(b => {
    b.addEventListener("click", async () => {
      await fetch(absUrl(`/api/pocs/${b.dataset.id}/toggle`), { method: "POST" });
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
        const r = await fetch(absUrl("/api/pocs/bulk"), {
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
