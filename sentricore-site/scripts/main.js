// Sentricore DNS site — progressive enhancements only (site works without JS)
(function () {
  "use strict";

  // Tabbed code panels (quickstart installers, etc.)
  document.querySelectorAll("[data-tabs]").forEach(function (tabs) {
    var buttons = tabs.querySelectorAll(".tab-btn");
    var panels = tabs.querySelectorAll(".tab-panel");
    buttons.forEach(function (btn) {
      btn.addEventListener("click", function () {
        buttons.forEach(function (b) {
          b.classList.remove("active");
          b.setAttribute("aria-selected", "false");
        });
        panels.forEach(function (p) { p.classList.remove("active"); });
        btn.classList.add("active");
        btn.setAttribute("aria-selected", "true");
        var target = tabs.querySelector('[data-panel="' + btn.dataset.tab + '"]');
        if (target) target.classList.add("active");
      });
    });
  });

  // Close mobile nav when a link is chosen
  document.querySelectorAll(".site-nav a").forEach(function (link) {
    link.addEventListener("click", function () {
      document.body.classList.remove("nav-open");
    });
  });

  // Copy-to-clipboard on fenced code blocks
  document.querySelectorAll("pre.codeblock").forEach(function (pre) {
    var wrap = document.createElement("div");
    wrap.style.position = "relative";
    pre.parentNode.insertBefore(wrap, pre);
    wrap.appendChild(pre);
    var btn = document.createElement("button");
    btn.textContent = "Copy";
    btn.className = "copy-btn";
    btn.style.cssText =
      "position:absolute;top:8px;right:8px;background:#1e293b;color:#94a3b8;" +
      "border:1px solid #24304d;border-radius:6px;font-size:0.72rem;padding:2px 8px;cursor:pointer;";
    btn.addEventListener("click", function () {
      navigator.clipboard.writeText(pre.innerText).then(function () {
        btn.textContent = "Copied!";
        setTimeout(function () { btn.textContent = "Copy"; }, 1500);
      });
    });
    wrap.appendChild(btn);
  });
})();
