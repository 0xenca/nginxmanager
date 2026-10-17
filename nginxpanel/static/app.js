// nginx-panel — JS sin dependencias (Chart.js y QRCode se cargan solo donde se usan)
(function () {
  "use strict";

  // menú móvil
  document.querySelectorAll("[data-toggle]").forEach(function (b) {
    b.addEventListener("click", function () {
      document.getElementById(b.dataset.toggle).classList.toggle("open");
    });
  });

  // confirmaciones
  document.querySelectorAll("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (e) {
      if (!confirm(f.dataset.confirm)) e.preventDefault();
    });
  });

  // grupos de hosts: plegar/desplegar (recordado en este navegador)
  var store = {
    get: function (k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) { /* sin almacenamiento */ } }
  };
  document.querySelectorAll(".group[data-group]").forEach(function (g) {
    var key = "np-group-collapsed-" + g.dataset.group;
    var btn = g.querySelector(".gtoggle");
    var apply = function (collapsed) {
      g.classList.toggle("collapsed", collapsed);
      btn.setAttribute("aria-expanded", String(!collapsed));
    };
    apply(store.get(key) === "1");
    btn.addEventListener("click", function () {
      var c = !g.classList.contains("collapsed");
      apply(c);
      store.set(key, c ? "1" : "0");
    });
  });

  // cerrar popovers al hacer clic fuera
  document.addEventListener("click", function (e) {
    document.querySelectorAll("details.pop[open]").forEach(function (d) {
      if (!d.contains(e.target)) d.removeAttribute("open");
    });
  });

  // búsqueda de hosts
  var hf = document.getElementById("hostfilter");
  if (hf) {
    hf.addEventListener("input", function () {
      var q = hf.value.trim().toLowerCase();
      var any = false;
      document.querySelectorAll(".hostrow").forEach(function (r) {
        var ok = !q || r.dataset.search.indexOf(q) !== -1;
        r.hidden = !ok;
        if (ok) any = true;
      });
      document.querySelectorAll(".group[data-group]").forEach(function (g) {
        var rows = g.querySelectorAll(".hostrow");
        var vis = g.querySelectorAll(".hostrow:not([hidden])").length;
        g.hidden = q !== "" && (rows.length === 0 || vis === 0);
        if (q && vis) g.classList.remove("collapsed");   // al buscar, abrir donde hay resultados
      });
      var nm = document.getElementById("nomatch");
      if (nm) nm.hidden = any || !q;
    });
  }

  // selección múltiple para mover hosts entre grupos
  var bulk = document.getElementById("bulk");
  if (bulk) {
    var sels = document.querySelectorAll("input.sel");
    var refresh = function () {
      var n = document.querySelectorAll("input.sel:checked").length;
      document.getElementById("bulkcount").textContent = n;
      bulk.hidden = n === 0;
    };
    sels.forEach(function (c) { c.addEventListener("change", refresh); });
    document.querySelectorAll("input.selall").forEach(function (all) {
      all.addEventListener("change", function () {
        all.closest("table").querySelectorAll("tr.hostrow:not([hidden]) input.sel").forEach(function (c) { c.checked = all.checked; });
        refresh();
      });
    });
    document.getElementById("bulkclear").addEventListener("click", function () {
      document.querySelectorAll("input.sel, input.selall").forEach(function (c) { c.checked = false; });
      refresh();
    });
  }

  // comprobación manual de estado de hosts (sin recargar la página)
  document.querySelectorAll("form[data-check]").forEach(function (f) {
    f.addEventListener("submit", function (e) {
      e.preventDefault();
      var btn = f.querySelector("button");
      var label = btn.textContent;
      var scope = f.querySelector("[name=scope]").value;
      var cells = scope === "all" ? document.querySelectorAll(".hscell")
        : scope.indexOf("group:") === 0 ? document.querySelectorAll('.group[data-group="' + scope.slice(6) + '"] .hscell')
        : document.querySelectorAll('.hscell[data-hid="' + scope.slice(5) + '"]');
      cells.forEach(function (c) { c.closest("tr").classList.add("checking"); });
      btn.classList.add("busy");
      btn.textContent = "Comprobando…";
      var msg = document.getElementById("checkmsg");
      fetch(f.action, { method: "POST", body: new FormData(f), credentials: "same-origin",
                        headers: { "Accept": "application/json" } })
        .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
        .then(function (d) {
          Object.keys(d.html).forEach(function (hid) {
            var cell = document.querySelector('.hscell[data-hid="' + hid + '"]');
            if (cell) cell.innerHTML = d.html[hid];
          });
          var bad = Object.keys(d.levels).filter(function (k) { return d.levels[k] === "error"; }).length;
          if (msg) msg.textContent = "· " + Object.keys(d.levels).length + " comprobados en " + d.elapsed + " s" +
            (bad ? " · " + bad + " con errores" : "");
        })
        .catch(function (err) { if (msg) msg.textContent = "· error al comprobar: " + err.message; })
        .finally(function () {
          cells.forEach(function (c) { c.closest("tr").classList.remove("checking"); });
          btn.classList.remove("busy");
          btn.textContent = label;
        });
    });
  });

  // campos condicionales: data-show-if='{"type":["proxy"]}'
  var form = document.querySelector("form.form");
  if (form) {
    var deps = form.querySelectorAll("[data-show-if]");
    var update = function () {
      deps.forEach(function (el) {
        var cond = JSON.parse(el.dataset.showIf);
        var ok = Object.keys(cond).every(function (k) {
          var input = form.elements[k];
          if (!input) return true;
          var v = input.type === "checkbox" ? String(input.checked) : input.value;
          return cond[k].map(String).indexOf(v) !== -1;
        });
        el.hidden = !ok;
      });
    };
    form.addEventListener("change", update);
    update();
  }

  // cert nuevo: mostrar bloque según tipo
  var kind = document.querySelector("select[name=kind]");
  if (kind) {
    var upd = function () {
      document.querySelectorAll("[data-kind]").forEach(function (el) {
        el.hidden = el.dataset.kind.split(" ").indexOf(kind.value) === -1;
      });
    };
    kind.addEventListener("change", upd);
    upd();
  }

  // seguimiento de tareas
  var job = document.getElementById("joblog");
  if (job && job.dataset.status === "running") {
    var poll = function () {
      fetch(job.dataset.url, { credentials: "same-origin" }).then(function (r) { return r.json(); }).then(function (d) {
        job.textContent = d.log;
        job.scrollTop = job.scrollHeight;
        var st = document.getElementById("jobstatus");
        if (d.status !== "running") {
          st.textContent = d.status === "ok" ? "Completada" : "Con errores";
          st.className = "tag " + (d.status === "ok" ? "ok" : "err");
          document.getElementById("jobdone").hidden = false;
        } else {
          setTimeout(poll, 1500);
        }
      }).catch(function () { setTimeout(poll, 3000); });
    };
    poll();
  }

  // QR para 2FA
  var qr = document.getElementById("qrcode");
  if (qr && window.QRCode) {
    new window.QRCode(qr, { text: qr.dataset.uri, width: 180, height: 180 });
  }

  // gráficas de analíticas
  var data = document.getElementById("chart-data");
  if (data && window.Chart) {
    var d = JSON.parse(data.textContent);
    var css = getComputedStyle(document.documentElement);
    var ink = css.getPropertyValue("--muted").trim();
    var grid = css.getPropertyValue("--line").trim();
    Chart.defaults.color = ink;
    Chart.defaults.borderColor = grid;
    Chart.defaults.font.family = css.getPropertyValue("--sans");
    var colors = { "2xx": "#159a5b", "3xx": "#2f6db3", "4xx": "#d29a2a", "5xx": "#c2412d", "blocked": "#7a4bb8" };
    var names = { "2xx": "2xx", "3xx": "3xx", "4xx": "4xx", "5xx": "5xx", "blocked": "Bloqueadas (WAF)" };
    new Chart(document.getElementById("reqChart"), {
      type: "bar",
      data: {
        labels: d.labels,
        datasets: Object.keys(colors).map(function (k) {
          return { label: names[k], data: d.series[k], backgroundColor: colors[k], borderWidth: 0, borderRadius: 2 };
        })
      },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false,
        interaction: { mode: "index", intersect: false },
        scales: { x: { stacked: true, grid: { display: false }, ticks: { maxTicksLimit: 12 } },
                  y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } },
        plugins: { legend: { position: "bottom", labels: { boxWidth: 10, boxHeight: 10 } } }
      }
    });
    new Chart(document.getElementById("bwChart"), {
      type: "line",
      data: { labels: d.labels, datasets: [{ label: "MB servidos", data: d.bytes.map(function (b) { return +(b / 1048576).toFixed(2); }),
        borderColor: "#159a5b", backgroundColor: "rgba(21,154,91,.12)", fill: true, pointRadius: 0, tension: .25, borderWidth: 2 }] },
      options: { responsive: true, maintainAspectRatio: false, animation: false,
        interaction: { mode: "index", intersect: false },
        scales: { x: { grid: { display: false }, ticks: { maxTicksLimit: 8 } }, y: { beginAtZero: true } },
        plugins: { legend: { display: false } } }
    });
  }
})();
