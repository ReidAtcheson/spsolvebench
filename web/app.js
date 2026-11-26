/* spsolvebench static frontend — zero framework, zero unsafe innerHTML on untrusted fields. */
(() => {
  const CFG = window.SPSOLVE_CONFIG;

  const state = {
    indexData: null,
    activeTab: "leaderboard",
    selectedRows: "8388608",
    searchQuery: "",
    sortBy: "elapsed_asc",
    entryCache: new Map(),
  };

  const $ = (id) => document.getElementById(id);

  function el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined) continue;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = String(v);
      else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, String(v));
    }
    for (const child of Array.isArray(children) ? children : [children]) {
      if (child === null || child === undefined) continue;
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    }
    return node;
  }

  function safeHttpUrl(url) {
    if (typeof url !== "string" || !url.trim()) return null;
    try {
      const u = new URL(url.trim());
      return u.protocol === "https:" || u.protocol === "http:" ? u.href : null;
    } catch {
      return null;
    }
  }

  function fmtDuration(seconds) {
    if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return "—";
    if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 2 : 1)} s`;
    const mins = Math.floor(seconds / 60);
    const rem = seconds - mins * 60;
    if (mins < 60) return `${mins}m ${rem.toFixed(1)}s`;
    const hrs = Math.floor(mins / 60);
    return `${hrs}h ${mins % 60}m ${Math.floor(rem)}s`;
  }

  function fmtCountdown(sec) {
    if (sec <= 0) return "NOW";
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = Math.floor(sec % 60);
    return `${String(h).padStart(2, "0")}h ${String(m).padStart(2, "0")}m ${String(s).padStart(2, "0")}s`;
  }

  function fmtRowsShort(rows) {
    if (rows === 8388608) return "2^23 (8.39M)";
    if (rows === 67108864) return "2^26 (67.1M)";
    const exp = Math.log2(rows);
    return Number.isInteger(exp) ? `2^${exp} (${rows.toLocaleString()})` : rows.toLocaleString();
  }

  function fmtBytes(n) {
    if (!Number.isFinite(n)) return "—";
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
    return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
  }

  function fmtSci(strOrNum) {
    if (strOrNum === null || strOrNum === undefined || strOrNum === "") return "—";
    const num = Number(strOrNum);
    return Number.isFinite(num) ? num.toExponential(2) : String(strOrNum);
  }

  function drandRoundUtc(rnd) {
    return CFG.DRAND_GENESIS_UTC + CFG.DRAND_PERIOD_S * (rnd - 1);
  }

  function upcomingRounds(nowUtc, count = 10) {
    const interval = CFG.ROUND_INTERVAL_S;
    let slot = (Math.floor(nowUtc / interval) + 1) * interval;
    const out = [];
    while (out.length < count) {
      const rnd = Math.floor((slot - CFG.DRAND_GENESIS_UTC) / CFG.DRAND_PERIOD_S) + 1;
      if (rnd >= CFG.LAUNCH_ROUND && drandRoundUtc(rnd) === slot) {
        out.push({ startRound: rnd, scheduledUtc: slot });
      }
      slot += interval;
    }
    return out;
  }

  function showBanner(msg) {
    const b = $("status-banner");
    if (!msg) {
      b.classList.add("hidden");
      b.textContent = "";
    } else {
      b.textContent = msg;
      b.classList.remove("hidden");
    }
  }

  async function fetchIndex() {
    const url = `${CFG.DATA_BASE}/public/index.json`;
    try {
      const res = await fetch(url, { cache: "no-cache" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      state.indexData = await res.json();
      showBanner("");
    } catch (err) {
      state.indexData = { total_entries: 0, generated_at: null, entries: [] };
      showBanner(
        `Could not load ${url} (${err.message}). Showing empty leaderboard—deploy the Worker/R2 bucket or pass ?data=... to preview local data.`
      );
    }
    renderAll();
  }

  function renderStats() {
    const entries = state.indexData?.entries || [];
    $("stat-total").textContent = String(entries.length);

    const best23 = entries.filter((e) => e.rows === 8388608).sort((a, b) => a.elapsed_ns - b.elapsed_ns)[0];
    const best26 = entries.filter((e) => e.rows === 67108864).sort((a, b) => a.elapsed_ns - b.elapsed_ns)[0];
    $("stat-best-23").textContent = best23 ? fmtDuration(best23.elapsed_s) : "—";
    $("stat-best-26").textContent = best26 ? fmtDuration(best26.elapsed_s) : "—";

    const uniqueKeys = new Set(entries.map((e) => e.pubkey));
    $("stat-entrants").textContent = String(uniqueKeys.size);

    const gen = state.indexData?.generated_at;
    $("stat-updated").textContent = gen ? new Date(gen).toISOString().replace("T", " ").slice(0, 19) + "Z" : "Never";
  }

  function filteredEntries() {
    const entries = (state.indexData?.entries || []).slice();
    const q = state.searchQuery.trim().toLowerCase();
    const filtered = entries.filter((e) => {
      if (state.selectedRows !== "all" && String(e.rows) !== state.selectedRows) return false;
      if (!q) return true;
      const hay = [
        e.display_name || "",
        e.solver_name || "",
        e.pubkey || "",
        e.pubkey_short || "",
        String(e.start_round),
        String(e.rows),
        e.id,
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });

    if (state.sortBy === "elapsed_asc") {
      filtered.sort((a, b) => a.elapsed_ns - b.elapsed_ns || (a.backward_2_upper_num ?? 1) - (b.backward_2_upper_num ?? 1));
    } else if (state.sortBy === "berr_asc") {
      filtered.sort((a, b) => (a.backward_2_upper_num ?? 1) - (b.backward_2_upper_num ?? 1) || a.elapsed_ns - b.elapsed_ns);
    } else if (state.sortBy === "newest") {
      filtered.sort((a, b) => String(b.verified_at).localeCompare(String(a.verified_at)));
    }
    return filtered;
  }

  function renderLeaderboard() {
    const tbody = $("leaderboard-tbody");
    tbody.replaceChildren();
    const rows = filteredEntries();

    if (rows.length === 0) {
      tbody.appendChild(
        el("tr", {}, el("td", { colspan: "8", class: "empty-cell", text: "No verified entries match this filter yet." }))
      );
      return;
    }

    rows.forEach((e, idx) => {
      const rank = idx + 1;
      const rankClass = rank <= 3 ? `rank-num rank-${rank}` : "rank-num";

      const solverLine = el("span", { class: "solver-title", text: e.solver_name || "Unnamed solver" });
      if (e.has_writeup) {
        solverLine.appendChild(el("span", { class: "badge badge-writeup", text: "writeup" }));
      }
      const entrantLine = el("span", {
        class: "entrant-sub mono",
        text: e.display_name ? `${e.display_name} · ${e.pubkey_short}` : e.pubkey_short,
      });

      const srParts = [];
      if (e.solve_wall_s != null) srParts.push(`solve ${fmtDuration(e.solve_wall_s)}`);
      if (e.peak_rss_mib != null) srParts.push(`${(e.peak_rss_mib / 1024).toFixed(2)} GiB`);

      const tr = el(
        "tr",
        { class: "clickable", onclick: () => openDetailModal(e) },
        [
          el("td", { class: `mono ${rankClass}`, text: `#${rank}` }),
          el("td", { class: "mono time-cell", text: fmtDuration(e.elapsed_s) }),
          el("td", { class: "mono", text: fmtSci(e.backward_2_upper) }),
          el("td", {}, [solverLine, entrantLine]),
          el("td", { class: "mono small", text: fmtRowsShort(e.rows) }),
          el("td", { class: "mono small", text: String(e.start_round) }),
          el("td", { class: "mono small muted", text: srParts.join(" · ") || "—" }),
          el("td", { class: "mono small" }, el("span", { class: "badge badge-pass", text: fmtBytes(e.proof_bytes) })),
        ]
      );
      tbody.appendChild(tr);
    });
  }

  function renderRounds() {
    const container = $("rounds-container");
    container.replaceChildren();
    const entries = state.indexData?.entries || [];
    if (entries.length === 0) {
      container.appendChild(el("div", { class: "panel-card muted", text: "No completed rounds yet." }));
      return;
    }

    const groups = new Map();
    for (const e of entries) {
      const k = `${e.start_round}:${e.rows}`;
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(e);
    }

    const sortedKeys = Array.from(groups.keys()).sort((a, b) => {
      const [ra, na] = a.split(":").map(Number);
      const [rb, nb] = b.split(":").map(Number);
      return rb - ra || nb - na;
    });

    for (const key of sortedKeys) {
      const list = groups.get(key).sort((a, b) => a.elapsed_ns - b.elapsed_ns);
      const bestNs = list[0].elapsed_ns;
      const [startRound, rows] = key.split(":").map(Number);
      const utcStr = new Date(list[0].start_scheduled_utc * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";

      const tblBody = el("tbody");
      list.forEach((e, idx) => {
        const ratio = bestNs > 0 ? (e.elapsed_ns / bestNs).toFixed(2) + "×" : "1.00×";
        tblBody.appendChild(
          el("tr", { class: "clickable", onclick: () => openDetailModal(e) }, [
            el("td", { class: "mono", text: `#${idx + 1}` }),
            el("td", { class: "mono time-cell", text: fmtDuration(e.elapsed_s) }),
            el("td", { class: "mono muted", text: idx === 0 ? "fastest" : ratio }),
            el("td", { class: "mono", text: fmtSci(e.backward_2_upper) }),
            el("td", { text: `${e.solver_name || "Unnamed"} (${e.display_name || e.pubkey_short})` }),
          ])
        );
      });

      const card = el("div", { class: "panel-card" }, [
        el("h3", { style: "margin-top:0", text: `Round ${startRound} · ${fmtRowsShort(rows)}` }),
        el("p", { class: "muted small mono", text: `${utcStr} · ${list.length} verified ${list.length === 1 ? "entry" : "entries"}` }),
        el("div", { class: "table-wrap" }, [
          el("table", { class: "data-table" }, [
            el("thead", {}, el("tr", {}, [
              el("th", { text: "#" }),
              el("th", { text: "Certified Time" }),
              el("th", { text: "vs. Fastest" }),
              el("th", { text: "Backward Error" }),
              el("th", { text: "Solver / Entrant" }),
            ])),
            tblBody,
          ]),
        ]),
      ]);
      container.appendChild(card);
    }
  }

  function renderEntrants() {
    const tbody = $("entrants-tbody");
    tbody.replaceChildren();
    const entries = state.indexData?.entries || [];
    if (entries.length === 0) {
      tbody.appendChild(el("tr", {}, el("td", { colspan: "6", class: "empty-cell", text: "No entrants yet." })));
      return;
    }

    const byKey = new Map();
    for (const e of entries) {
      if (!byKey.has(e.pubkey)) {
        byKey.set(e.pubkey, { pubkey: e.pubkey, pubkey_short: e.pubkey_short, entries: [] });
      }
      byKey.get(e.pubkey).entries.push(e);
    }

    const list = Array.from(byKey.values()).sort((a, b) => b.entries.length - a.entries.length);
    for (const grp of list) {
      const sortedByDate = grp.entries.slice().sort((a, b) => String(b.verified_at).localeCompare(String(a.verified_at)));
      const latest = sortedByDate[0];
      const b23 = grp.entries.filter((e) => e.rows === 8388608).sort((a, b) => a.elapsed_ns - b.elapsed_ns)[0];
      const b26 = grp.entries.filter((e) => e.rows === 67108864).sort((a, b) => a.elapsed_ns - b.elapsed_ns)[0];

      tbody.appendChild(
        el("tr", {}, [
          el("td", {}, [
            el("span", { class: "solver-title", text: latest.display_name || "Anonymous Key" }),
            el("span", { class: "entrant-sub mono", text: grp.pubkey_short }),
          ]),
          el("td", { class: "mono", text: String(grp.entries.length) }),
          el("td", { class: "mono time-cell", text: b23 ? fmtDuration(b23.elapsed_s) : "—" }),
          el("td", { class: "mono time-cell", text: b26 ? fmtDuration(b26.elapsed_s) : "—" }),
          el("td", { text: latest.solver_name || "—" }),
          el(
            "td",
            {},
            el("button", {
              class: "btn-secondary small",
              text: "Filter Runs",
              onclick: () => {
                state.selectedRows = "all";
                state.searchQuery = grp.pubkey;
                $("search-input").value = grp.pubkey;
                document.querySelectorAll(".tier-pill").forEach((p) => {
                  p.classList.toggle("active", p.dataset.rows === "all");
                });
                switchTab("leaderboard");
                renderLeaderboard();
              },
            })
          ),
        ])
      );
    }
  }

  async function openDetailModal(summaryRow) {
    const modal = $("detail-modal");
    const body = $("modal-body");
    $("modal-title").textContent = summaryRow.solver_name || "Verified Submission";
    $("modal-subtitle").textContent = `Attempt ${summaryRow.id}`;
    body.replaceChildren(el("p", { class: "muted", text: "Loading verified record…" }));
    modal.classList.remove("hidden");

    let full = state.entryCache.get(summaryRow.id);
    if (!full) {
      try {
        const res = await fetch(`${CFG.DATA_BASE}/verified/${summaryRow.id}/entry.json`, { cache: "no-cache" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        full = await res.json();
        state.entryCache.set(summaryRow.id, full);
      } catch (err) {
        body.replaceChildren(el("p", { class: "muted", text: `Failed to load entry.json: ${err.message}` }));
        return;
      }
    }

    const cert = full.certified;
    const ent = full.entrant;
    const art = full.artifacts;
    const proofUrl = `${CFG.DATA_BASE}/${art.proof_path}`;

    const kv = el("div", { class: "kv-grid" }, [
      el("div", { class: "kv-item" }, [el("span", { class: "k", text: "Certified Time" }), el("span", { class: "v", text: `${fmtDuration(cert.elapsed_s)} (±${(cert.clock_uncertainty_ns / 1e9).toFixed(1)}s)` })]),
      el("div", { class: "kv-item" }, [el("span", { class: "k", text: "Backward Error Upper" }), el("span", { class: "v", text: cert.backward_2_upper })]),
      el("div", { class: "kv-item" }, [el("span", { class: "k", text: "Matrix Size" }), el("span", { class: "v", text: fmtRowsShort(full.rows) })]),
      el("div", { class: "kv-item" }, [el("span", { class: "k", text: "Start → Proof Round" }), el("span", { class: "v", text: `${full.start_round} → ${full.proof_round}` })]),
      el("div", { class: "kv-item" }, [el("span", { class: "k", text: "Entrant Identity" }), el("span", { class: "v", text: ent.display_name ? `${ent.display_name} (${ent.pubkey_short})` : ent.pubkey_short })]),
      el("div", { class: "kv-item" }, [el("span", { class: "k", text: "Proof Size / SHA-256" }), el("span", { class: "v", text: `${fmtBytes(art.proof_bytes)} · ${art.proof_sha256.slice(0, 16)}…` })]),
    ]);

    const children = [kv];

    const safeRepo = safeHttpUrl(ent.repo_url);
    if (safeRepo) {
      children.push(
        el("div", {}, [
          el("span", { class: "muted small", text: "Repository: " }),
          el("a", { href: safeRepo, target: "_blank", rel: "noopener noreferrer", text: safeRepo }),
        ])
      );
    }

    if (ent.description_hidden) {
      children.push(
        el("div", {
          class: "banner",
          text: "Free-text descriptions for this entry were withheld by automated moderation. The cryptographically certified numerical score and replayable proof remain valid.",
        })
      );
    } else {
      if (ent.compute_description) {
        children.push(
          el("div", {}, [
            el("h3", { style: "margin:0 0 6px", text: "Compute Description" }),
            el("div", { class: "writeup-box", text: ent.compute_description }),
          ])
        );
      }
      if (ent.algorithm_description) {
        children.push(
          el("div", {}, [
            el("h3", { style: "margin:0 0 6px", text: "Algorithm Description" }),
            el("div", { class: "writeup-box", text: ent.algorithm_description }),
          ])
        );
      }
    }

    const replayCmd = [
      `curl -fsSLO "${proofUrl}"`,
      `python3 -c 'import pathlib; p=pathlib.Path("proof.bin").read_bytes(); pathlib.Path("reg").write_bytes(p[8:152]); pathlib.Path("winner.digest").write_bytes(p[200:232])'`,
      `./stencil verify-beacon reg examples/tsa/sigstore-root.crt ${CFG.TSA_POLICY_OID} winner.digest proof.bin`,
    ].join("\n");

    children.push(
      el("div", {}, [
        el("h3", { style: "margin:0 0 8px", text: "Independent Offline Replay" }),
        el("div", { style: "margin-bottom:10px" }, [
          el("a", {
            class: "btn-primary",
            href: proofUrl,
            download: `proof-${full.id.slice(0, 12)}.bin`,
            text: `Download proof.bin (${fmtBytes(art.proof_bytes)})`,
          }),
        ]),
        el("pre", { class: "code-block", text: replayCmd }),
      ])
    );

    body.replaceChildren(...children);
  }

  function closeModal() {
    $("detail-modal").classList.add("hidden");
  }

  function renderScheduleTick() {
    const nowSec = Math.floor(Date.now() / 1000);
    $("footer-utc").textContent = new Date(nowSec * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";

    const list = upcomingRounds(nowSec, 10);
    if (list.length > 0) {
      const next = list[0];
      $("next-round-countdown").textContent = fmtCountdown(next.scheduledUtc - nowSec);
      $("next-round-meta").textContent = `round ${next.startRound} · ${new Date(next.scheduledUtc * 1000).toISOString().slice(11, 16)} UTC`;
    }

    const tbody = $("schedule-tbody");
    tbody.replaceChildren();
    for (const r of list) {
      const d = new Date(r.scheduledUtc * 1000);
      tbody.appendChild(
        el("tr", {}, [
          el("td", { class: "mono", text: String(r.startRound) }),
          el("td", { class: "mono small", text: d.toISOString().replace("T", " ").slice(0, 19) + "Z" }),
          el("td", { class: "mono small muted", text: d.toLocaleString() }),
          el("td", { class: "mono small", text: fmtCountdown(r.scheduledUtc - nowSec) }),
        ])
      );
    }
  }

  function setupStaticDocs() {
    $("dl-index").href = `${CFG.DATA_BASE}/public/index.json`;
    $("dl-dataset").href = `${CFG.DATA_BASE}/public/dataset.jsonl.gz`;

    $("cli-snippet").textContent = [
      "# 1. Generate a reusable Ed25519 keypair (groups your submissions)",
      "python3 client/spsolve_bench.py keygen --out my.key",
      "",
      "# 2. Run on the next official 5/day UTC round (2^23 or 2^26 rows)",
      "python3 client/spsolve_bench.py run --key my.key \\",
      "  --stencil-dir /path/to/sparse-solver-challenge \\",
      "  --work-dir ./run1 --rows 8388608 --proof-window-s 3600 \\",
      "  --solver-cmd ./my_solver",
      "",
      "# 3. Sign, solve Hashcash PoW, and submit",
      `python3 client/spsolve_bench.py submit --key my.key \\`,
      `  --api ${CFG.API_BASE} --proof ./run1/public/proof.bin \\`,
      `  --display-name "My Team" --solver-name "my-solver-v1" \\`,
      `  --compute-description "8-core Zen 3, 32 GiB RAM" \\`,
      `  --algorithm-description "Multifrontal LDLT + GMRES refinement"`,
    ].join("\n");
  }

  async function sha256Bytes(bytes) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  }

  function toHex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function leadingZeroBits(bytes) {
    let bits = 0;
    for (let i = 0; i < bytes.length; i++) {
      if (bytes[i] === 0) bits += 8;
      else {
        bits += Math.clz32(bytes[i]) - 24;
        break;
      }
    }
    return bits;
  }

  async function solvePowBrowser(proofSha, metaSha, pubkey, bucket, bits, onProgress) {
    const enc = new TextEncoder();
    const prefix = `spsolve-submit-pow-v1\n${proofSha}\n${metaSha}\n${pubkey}\n${bucket}\n`;
    let n = 0;
    while (true) {
      for (let batch = 0; batch < 2500; batch++, n++) {
        const nonce = n.toString(16);
        const h = await sha256Bytes(enc.encode(prefix + nonce));
        if (leadingZeroBits(h) >= bits) return nonce;
      }
      if (onProgress) onProgress(n);
      await new Promise((r) => setTimeout(r, 0));
    }
  }

  function setupForms() {
    $("upload-form").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const btn = $("upload-btn");
      const statusEl = $("upload-status");
      statusEl.className = "upload-status";
      statusEl.classList.remove("hidden");
      btn.disabled = true;

      try {
        const proofFile = $("file-proof").files[0];
        const metaFile = $("file-metadata").files[0];
        const sigHex = $("input-sig").value.trim().toLowerCase();
        if (!proofFile || !metaFile) throw new Error("Select both proof.bin and metadata.json.");

        const proofBytes = new Uint8Array(await proofFile.arrayBuffer());
        const metaBytes = new Uint8Array(await metaFile.arrayBuffer());
        const metaObj = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(metaBytes));
        if (!metaObj.pubkey || !/^[0-9a-f]{64}$/.test(metaObj.pubkey)) {
          throw new Error("metadata.json must contain a 64-char hex pubkey.");
        }

        let powBits = CFG.POW_BITS;
        let bucketS = CFG.POW_BUCKET_S;
        try {
          const hRes = await fetch(`${CFG.API_BASE}/health`);
          if (hRes.ok) {
            const h = await hRes.json();
            powBits = Number(h.submission?.pow_bits ?? powBits);
            bucketS = Number(h.submission?.pow_bucket_s ?? bucketS);
          }
        } catch {
          // fall back to static config
        }

        const proofSha = toHex(await sha256Bytes(proofBytes));
        const metaSha = toHex(await sha256Bytes(metaBytes));
        const bucket = Math.floor(Date.now() / 1000 / bucketS);

        statusEl.textContent = `Solving ${powBits}-bit anti-abuse PoW in browser…`;
        const nonce =
          powBits > 0
            ? await solvePowBrowser(proofSha, metaSha, metaObj.pubkey, bucket, powBits, (n) => {
                statusEl.textContent = `Solving ${powBits}-bit anti-abuse PoW… (${n.toLocaleString()} hashes)`;
              })
            : "0";

        statusEl.textContent = "Uploading certificate…";
        const form = new FormData();
        form.set("proof", new Blob([proofBytes], { type: "application/octet-stream" }), "proof.bin");
        form.set("metadata", new Blob([metaBytes], { type: "application/json" }), "metadata.json");
        form.set("sig", sigHex);
        form.set("pow_bucket", String(bucket));
        form.set("pow_nonce", nonce);

        const res = await fetch(`${CFG.API_BASE}/submit`, { method: "POST", body: form });
        const body = await res.json();
        if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);

        statusEl.classList.add("ok");
        statusEl.textContent = `Accepted (${body.status}): attempt ${body.id}. Queued for the next 5×/day batch verification run.`;
        $("status-id-input").value = body.id;
      } catch (err) {
        statusEl.classList.add("err");
        statusEl.textContent = `Submission failed: ${err.message}`;
      } finally {
        btn.disabled = false;
      }
    });

    $("status-form").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const id = $("status-id-input").value.trim().toLowerCase();
      const out = $("status-output");
      out.classList.remove("hidden");
      out.textContent = "Checking…";
      try {
        const res = await fetch(`${CFG.API_BASE}/status/${encodeURIComponent(id)}`);
        const data = await res.json();
        out.textContent = JSON.stringify(data, null, 2);
      } catch (err) {
        out.textContent = `Error: ${err.message}`;
      }
    });
  }

  function switchTab(tabName) {
    state.activeTab = tabName;
    document.querySelectorAll(".nav-tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === tabName));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${tabName}`));
  }

  function renderAll() {
    renderStats();
    renderLeaderboard();
    renderRounds();
    renderEntrants();
  }

  function init() {
    document.querySelectorAll(".nav-tab").forEach((btn) => {
      btn.addEventListener("click", () => switchTab(btn.dataset.tab));
    });

    document.querySelectorAll(".tier-pill").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.selectedRows = btn.dataset.rows;
        document.querySelectorAll(".tier-pill").forEach((p) => p.classList.toggle("active", p === btn));
        renderLeaderboard();
      });
    });

    $("search-input").addEventListener("input", (e) => {
      state.searchQuery = e.target.value;
      renderLeaderboard();
    });

    $("sort-select").addEventListener("change", (e) => {
      state.sortBy = e.target.value;
      renderLeaderboard();
    });

    $("modal-close").addEventListener("click", closeModal);
    $("modal-backdrop").addEventListener("click", closeModal);
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closeModal();
    });

    setupStaticDocs();
    setupForms();
    renderScheduleTick();
    setInterval(renderScheduleTick, 1000);
    fetchIndex();
  }

  init();
})();
