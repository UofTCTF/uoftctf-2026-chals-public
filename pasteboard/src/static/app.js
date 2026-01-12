(function () {
  const n = document.getElementById("rawMsg");
  const raw = n ? n.textContent : "";
  const card = document.getElementById("card");

  try {
    const cfg = window.renderConfig || { mode: (card && card.dataset.mode) || "safe" };
    const mode = cfg.mode.toLowerCase();
    const clean = DOMPurify.sanitize(raw, { ALLOW_DATA_ATTR: false });
    if (card) {
      card.innerHTML = clean;
    }
    if (mode !== "safe") {
      console.log("Render mode:", mode);
    }
  } catch (err) {
    window.lastRenderError = err ? String(err) : "unknown";
    handleError();
  }

  function handleError() {
    const el = document.getElementById("errorReporterScript");
    if (el && el.src) {
      return;
    }

    const c = window.errorReporter || { path: "/telemetry/error-reporter.js" };
    const p = c.path && c.path.value
      ? c.path.value
      : String(c.path || "/telemetry/error-reporter.js");
    const s = document.createElement("script");
    s.id = "errorReporterScript";
    let src = p;
    try {
      src = new URL(p).href;
    } catch (err) {
      src = p.startsWith("/") ? p : "/telemetry/" + p;
    }
    s.src = src;

    if (el) {
      el.replaceWith(s);
    } else {
      document.head.appendChild(s);
    }
  }
})();
