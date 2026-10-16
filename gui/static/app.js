/* CTFScanner 前端脚本：任务状态轮询、日志尾部加载、POC 管理、任务创建。 */

// 后台路径随机化（续138）：模板里的 url_for() 会自动带前缀，JS **不会** ⇒ 绝对 URL 一律过 absUrl()。
// 基路径取自 base.html 的 name="ctf-base"（＝request.script_root；挂在根路径时是空串，行为与改动前一致）。
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

/* 任务详情页签切换：资产页签的翻页与筛选都是**整页刷新**，链接尾部带锚点（#sites / #dirs / …），
   这里据此回到原页签 —— 否则翻一页就掉回「潜在漏洞」，看着像"翻页没生效"。认不出锚点就保持默认页签。 */
function initTabs() {
  const tabs = [...document.querySelectorAll(".tab[data-tab]")];
  const show = t => {
    tabs.forEach(x => x.classList.remove("active"));
    document.querySelectorAll(".tabpane").forEach(p => p.classList.remove("active"));
    t.classList.add("active");
    const pane = document.getElementById("pane-" + t.dataset.tab);
    if (pane) pane.classList.add("active");
  };
  tabs.forEach(t => t.addEventListener("click", () => {
    show(t);
    // 续195（主理人点单）：点页签也写进 URL —— 否则随后任何整页刷新（停止/重启/删除后的
    // reload、表单提交后的 302）都掉回默认页签「潜在漏洞」，看着像"点其他功能被送去漏洞页"
    history.replaceState(null, "", "#" + t.dataset.tab);
  }));
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
    // 续201：同上 —— 保住当前页签（这是行内 taskOp 的刷新路径）
    setTimeout(() => location.replace(location.pathname + location.search + location.hash), 700);
  } catch (e) {
    say("网络错误");
    if (btn) btn.disabled = false;
  }
}

/* 绑定容器内的 [data-op] 按钮 */
function bindTaskOps(scope, msgEl) {
  document.querySelectorAll(`${scope} button[data-op]`).forEach(b => {
    // 去重：DOMContentLoaded 与详情页内联脚本会各绑一次，重复绑定＝"停止/重启/删除"各发两次 POST。
    // 先绑的那个生效（内联脚本先执行、带 msgEl，操作反馈仍显示）。
    if (b.dataset.opBound) return;
    b.dataset.opBound = "1";
    b.addEventListener("click", () => taskOp(b.dataset.op, b.dataset.id, b, msgEl));
  });
}

/* ---------- 续201：详情页页签的"提交后别丢" ---------- */
/* 服务端渲染时不知道用户停在哪个页签（hash 从不发到服务器），所以由前端在提交前把当前
   hash 塞进表单；后端 redirect 时用 `_with_hash()` 拼回去。 */
function initDetailTabPersist() {
  if (!document.getElementById("pane-vulns")) return;      // 不是任务详情页
  document.querySelectorAll("form[method=post]").forEach(form => {
    if (form.dataset.hashBound) return;
    form.dataset.hashBound = "1";
    form.addEventListener("submit", () => {
      const h = (location.hash || "").replace(/^#/, "");
      if (!h) return;
      let f = form.querySelector("input[name=next_hash]");
      if (!f) {
        f = document.createElement("input");
        f.type = "hidden"; f.name = "next_hash";
        form.appendChild(f);
      }
      f.value = "#" + h;
    });
  });
}

function initTaskTable() {
  const rows = [...document.querySelectorAll("#task-rows tr[data-id]")];
  if (!rows.length) return;

  // 1) 筛选已搬到**服务端**（续53）：`/tasks` 分页后，前端筛选只会筛当前页，比原来更误导。
  //    上面的 `rows` 仍要保留 —— 第 5 步轮询要用它（别顺手删掉）。

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
    // 续200：导出搬进这一排了。它**不是** `/api/tasks/bulk` 的 action（那三者改任务状态、
    // 回 JSON；导出回的是文件），单独走 `/api/tasks/export` 并触发下载。
    if (action === "export") { return bulkExport(ids, bulkMsg); }
    bulkMsg.textContent = "提交中…";
    try {
      const r = await fetch(absUrl("/api/tasks/bulk"), {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, ids }),
      });
      const j = await r.json();
      bulkMsg.textContent = j.error ? j.error
        : `已处理 ${j.affected} 个${j.skipped && j.skipped.length ? `，跳过 ${j.skipped.length} 个（状态不符）` : ""}`;
      // 续201：reload 要**保住当前页签** —— `location.reload()` 会连 hash 一起丢，
      // 于是停止/重启/删除之后必定掉回第一个页签「潜在漏洞」（主理人报的就是这个）。
      setTimeout(() => location.replace(location.pathname + location.search + location.hash), 700);
    } catch (e) { bulkMsg.textContent = "网络错误"; }
  };
  document.querySelectorAll("[data-bulk]").forEach(b =>
    b.addEventListener("click", () => bulk(b.dataset.bulk)));

  // 续200：勾选后**导出** —— 一个任务直接下载那一份；多个任务打包 zip（后端给
  // Content-Disposition，这里只负责把字节变成一个本地文件，不 reload 页面）。
  async function bulkExport(ids, msgEl) {
    msgEl.textContent = "生成中…";
    try {
      const r = await fetch(absUrl("/api/tasks/export"), {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ids, fmt: "md" }),
      });
      if (!r.ok) {
        const j = await r.json().catch(() => ({}));
        msgEl.textContent = j.error || `导出失败（HTTP ${r.status}）`;
        return;
      }
      const disp = r.headers.get("Content-Disposition") || "";
      const m = /filename=([^;]+)/.exec(disp);
      const name = m ? m[1].replace(/["']/g, "") : "tasks_export.zip";
      const blob = await r.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(a.href);
      msgEl.textContent = `已导出 ${ids.length} 个任务`;
    } catch (e) {
      msgEl.textContent = "导出失败（网络错误）";
    }
  }

  // 4) 行内操作（查看/导出是链接；停止/重启/删除走 API）
  bindTaskOps("#task-rows", bulkMsg);

  // 5) 轮询未完成任务的状态：续93 改成**一次批量**请求。原先逐行各问一次 `/api/tasks/<id>/status`，
  //    页大小 100 就是每 2.5 秒 100 个请求，而每个响应后端都要 `_tail()` 整份读一遍日志（列表页根本不显示）。
  //    现在只问还没结束的行，全跑完就停表。
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

/* 新建任务表单的"一键批量勾选"（续118）。判据只有一份、来自模板：`[data-ck-group]` 划分组，
   `data-ck-default` 说"刚打开该不该勾"。JS **不认识任何阶段名** —— 清单是 `runner.STAGE_ORDER`
   在后端渲染的，这里再抄一份迟早漂。按钮只改勾选状态：不提交、不清目标、不碰登录态。 */
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
// 弹窗拦截只认「用户手势」⇒ 必须在 click 里**同步**逐个 window.open（塞进 setTimeout/await 之后
// 就被拦成"只开第一个"）。上限 20 是防手滑，超出如实报；只开标签页、不发请求。
// 勾哪张表由按钮自己的 `data-pick-from` 给出（任务详情＝#tbl-detail-sites、跨任务页＝#tbl-all-sites）：
// 写死表 id 就等于"只有那一页能用"，别的页面接上来只会静默失灵（续145 之前的毛病）。
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
    // 浏览器的硬策略：**一次手势只放行一个 window.open**，后面的同步调用直接拿到 null。
    // 旧实现一律记成"被弹窗拦截，请允许后再试"—— 可即便允许，第二个照样开不出来。所以第一个直接开，
    // **其余渲染成真实链接**（点每个链接各自是一次手势），再给一份"复制链接清单"。
    let first = null;
    try { first = window.open(list[0], "_blank"); } catch (e) { first = null; }
    if (first) { try { first.opener = null; } catch (e) { /* 跨域句柄，忽略 */ } }
    if (box && rest.length) {
      const tip = document.createElement("div");
      tip.className = "muted small";
      // 续201：把"为什么"说在前面 —— 这是浏览器的硬策略（一次用户手势只放行一个window.open），不是本工具的限制；允许本站点弹出窗口后能一次多开几个。
      tip.textContent = `浏览器只允许一次点击开一个标签页，所以第 1 个已自动打开；`
        + `剩下 ${rest.length} 个点下面任意一条各开一个`
        + `（地址栏若提示\"允许弹出式窗口\"，点允许后重试可一次多开）：`;
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
      // 续195（主理人点单"批量打开只能打开一个网页"）：面板自动滚入视野 ——
      // 浏览器一次手势只放行一个 window.open 是硬策略，其余必须逐个点；
      // 面板在首屏之下时用户根本看不见，才觉得"只开了一个"
      if (box.scrollIntoView) box.scrollIntoView({ behavior: "smooth", block: "nearest" });
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

/* ---------- 预览框（续196：灯箱泛化）—— pvOpen(字符串或节点) 打开 / Esc·遮罩·关闭钮关闭 ---------- */
const pvEsc = s => String(s == null ? "" : s).replace(/[&<>"']/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function pvOpen(content) {
  const ov = document.getElementById("pv-overlay"), body = document.getElementById("pv-body");
  if (!ov || !body) return;
  // 字符串只接受**我们自己生成**的 HTML（任务名/域名都过 pvEsc）；节点（截图 img）直接用
  if (typeof content === "string") {
    const t = document.createElement("template");
    t.innerHTML = content.trim();
    body.replaceChildren(t.content);
  } else {
    body.replaceChildren(content);
  }
  ov.classList.add("open"); ov.setAttribute("aria-hidden", "false");
}
function pvShut() {
  const ov = document.getElementById("pv-overlay"), body = document.getElementById("pv-body");
  if (!ov || !body) return;
  ov.classList.remove("open"); body.replaceChildren(); ov.setAttribute("aria-hidden", "true");
}
function initPreview() {
  const ov = document.getElementById("pv-overlay");
  if (!ov) return;
  const close = document.getElementById("pv-close");
  if (close) close.addEventListener("click", pvShut);
  ov.addEventListener("click", e => { if (e.target === ov) pvShut(); });
  document.addEventListener("keydown", e => { if (e.key === "Escape") pvShut(); });
}
/* 站点截图大图：预览框机制的图片用法（同一机制，不另起第二份） */
function initLightbox() {
  document.addEventListener("click", e => {
    const t = e.target.closest && e.target.closest(".shot-thumb");
    if (t && t.dataset.full) {
      e.preventDefault();
      const img = document.createElement("img");
      img.className = "pv-img"; img.alt = "站点截图大图"; img.src = t.dataset.full;
      pvOpen(img);
    }
  });
}
/* ---------- 任务页「子任务/统计」预览框（续196，主理人点单：不要行内展开） ---------- */
function pvSubtreeHtml(d) {
  const head = `<h3>子任务（#${pvEsc(d.root.id)} ${pvEsc(d.root.name)}`
    + (d.total ? `，共 ${pvEsc(d.total)} 个` : "") + `）</h3>`;
  if (!d.nodes || !d.nodes.length) {
    return head + `<p class="pv-note">这个任务名下还没有子任务`
      + `（拓展域名送去探测、自动递归才会长出下一层）。</p>`;
  }
  const rows = d.nodes.map(n => {
    const c = n.counts || {};
    return `<tr><td class="mono">${pvEsc(n.label)}</td>`
      + `<td style="padding-left:${8 + (n.depth - 1) * 14}px">${pvEsc(n.name)}</td>`
      + `<td class="muted">${pvEsc(n.target || "-")}</td>`
      + `<td class="muted">站点 ${pvEsc(c.sites || 0)}<br>子域名 ${pvEsc(c.subs_own || 0)}`
      + `<br>漏洞 ${pvEsc(c.vulns || 0)}<br>拓展 ${pvEsc(c.subs_ext || 0)}</td>`
      + `<td class="muted mono">${pvEsc(n.stages || "-")}</td>`
      + `<td><span class="badge st-${pvEsc(n.status)}">${pvEsc(n.status)}</span></td>`
      + `<td>${pvEsc(n.progress)}%</td>`
      + `<td class="muted">${pvEsc(n.created_at || "-")}</td>`
      + `<td class="muted">${pvEsc(n.duration || "-")}</td>`
      + `<td><a class="btn-mini" href="/tasks/${pvEsc(n.id)}">查看结果</a></td></tr>`;
  }).join("");
  return head + `<table><thead><tr><th>编号</th><th>任务名</th><th>目标</th><th>统计</th>`
    + `<th>阶段</th><th>状态</th><th>进度</th><th>开始时间</th><th>时长</th><th></th></tr></thead>`
    + `<tbody>${rows}</tbody></table>`
    + `<p class="pv-note">各层同号字，层级只靠缩进；编号 24-a 规则：根任务的子任务按序 a/b/c，`
    + `孙任务 a-1/a-2。</p>`;
}
function pvStatsHtml(d) {
  const rows = d.rows.map(r => `<tr><td>${pvEsc(r.kind)}</td><td>${pvEsc(r.total)}</td>`
    + `<td class="muted">${pvEsc(r.by_task || "-")}</td></tr>`).join("");
  const tasks = (d.tasks || []).map(t =>
    `<span class="badge">#${pvEsc(t.id)} ${pvEsc(t.name)}</span>`).join(" ");
  return `<h3>统计（整棵衍生树资产汇聚）</h3>`
    + `<p class="pv-note">汇聚范围：根任务 #${pvEsc(d.root.id)} 起整棵树共 ${pvEsc(d.total_tasks)} 个任务；`
    + `同名资产跨任务去重（子域名按域名、站点按 URL、漏洞按主机+规则、邮箱按地址）。</p>`
    + `<table><thead><tr><th>资产类型</th><th>汇聚后数量</th><th>按来源任务拆分</th></tr></thead>`
    + `<tbody>${rows}</tbody></table><p class="pv-note">${tasks}</p>`;
}
// 续200：「阶段」预览框 —— 列出全部阶段，标明这个任务跑不跑、策略开关是什么状态。
// 三态要说清：**没这个开关**（enabled 为 null，总跑）/ **开关开着** / **开关关着**，
// 混成"关着"会让人以为是配置错了。
function pvStagesHtml(d) {
  const rows = (d.stages || []).map(s => {
    const on = s.in_task;
    const gate = s.enabled === null ? '<span class="muted small">无开关（总跑）</span>'
      : (s.enabled ? '<span class="badge">策略开启</span>'
                   : '<span class="muted small">策略关闭</span>');
    return `<tr class="${on ? "" : "muted"}"><td>${s.seq}</td><td class="mono">${pvEsc(s.name)}</td>`
      + `<td>${pvEsc(s.label)}</td><td>${on ? '<span class="badge">本任务含</span>'
                                            : '<span class="muted small">未选</span>'}</td>`
      + `<td>${gate}</td></tr>`;
  }).join("");
  const picked = (d.stages || []).filter(s => s.in_task).length;
  return `<h3 class="pv-title">${pvEsc(d.task && d.task.name || "")} · 阶段</h3>`
    + `<table><thead><tr><th>#</th><th>阶段</th><th>名称</th><th>本任务</th>`
    + `<th>策略开关</th></tr></thead><tbody>${rows}</tbody></table>`
    + `<p class="pv-note">本任务共选 ${picked} / ${(d.stages || []).length} 个阶段；`
    + `「策略关闭」的阶段即使选了也会被跳过（不发请求）。</p>`;
}
function initTaskPreview() {
  document.addEventListener("click", async e => {
    const b = e.target.closest && e.target.closest("button[data-pv]");
    if (!b) return;
    const id = b.dataset.id, kind = b.dataset.pv;
    pvOpen(`<p class="pv-note">加载中…</p>`);
    try {
      const path = kind === "stats" ? "stats" : (kind === "stages" ? "stages" : "subtasks");
      const url = absUrl(`/api/tasks/${id}/${path}`);
      const r = await fetch(url);
      const d = await r.json();
      if (!d.ok) { pvOpen(`<p class="pv-note">${pvEsc(d.error || "加载失败")}</p>`); return; }
      pvOpen(kind === "stats" ? pvStatsHtml(d)
             : kind === "stages" ? pvStagesHtml(d) : pvSubtreeHtml(d));
    } catch (err) {
      pvOpen(`<p class="pv-note">加载失败：${pvEsc(err && err.message ? err.message : err)}</p>`);
    }
  });
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
      // 续146：只读**按钮所在那个面板**里的勾选。此前读整页 `.pick-row:checked`，于是勾了站点行、
      // 切到漏洞页签点「批量确认存在」就会把**站点 URL** 当漏洞 id 发出去（服务端按非法 id 忽略 ⇒
      // 现象只是"点了没反应"）。按**容器**收而不按表 id 收：两页的表分别叫 `#tbl-vulns-all` 与 `#tbl-vulns`，
      // 写死任何一个另一页就失灵 —— 与「批量打开」的 `data-pick-from` 同一个教训。
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

/* ---------- 续151（用户点单）：curl / Python 脚本一键复制 ---------- */
// `[data-copy="#id"]` 指到要复制的那个元素（<pre>）；非安全上下文里 clipboard 不可用则退回选中文本。
function initCopyButtons() {
  document.querySelectorAll("button[data-copy]").forEach(b => {
    if (b.dataset.copyBound) return;
    b.dataset.copyBound = "1";
    const label = b.textContent;
    b.addEventListener("click", async () => {
      const el = document.querySelector(b.dataset.copy);
      if (!el) return;
      const text = el.textContent || "";
      let ok = false;
      try { await navigator.clipboard.writeText(text); ok = true; } catch (e) {
        const ta = document.createElement("textarea");
        ta.value = text; document.body.appendChild(ta); ta.select();
        try { ok = document.execCommand("copy"); } catch (e2) { ok = false; }
        document.body.removeChild(ta);
      }
      b.textContent = ok ? "已复制" : "复制失败，请手动选取";
      setTimeout(() => { b.textContent = label; }, 1200);
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initPreview();       // 续196：预览框机制（遮罩/关闭钮/Esc 只绑一次）
  initTaskPreview();   // 续196：任务页「子任务/统计」按钮 → 预览框
  initTabs();
  initDetailTabPersist();   // 续201：详情页表单提交前带上当前页签
  initFilters();
  initCollapsiblePanels();
  initPickAll();
  initTaskCheckAll();
  initOpenSites();
  initVulnReview();
  initLightbox();
  initCopyButtons();
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
