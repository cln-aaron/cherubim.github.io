(function () {
  "use strict";
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  var y = document.getElementById("year");
  if (y) y.textContent = new Date().getFullYear();

  var nav = document.getElementById("nav");
  var toggle = document.getElementById("navToggle");
  if (toggle && nav) {
    toggle.addEventListener("click", function () {
      var open = nav.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    nav.querySelectorAll(".nav-links a").forEach(function (a) {
      a.addEventListener("click", function () { nav.classList.remove("open"); toggle.setAttribute("aria-expanded", "false"); });
    });
  }

  var bar = document.getElementById("progress");
  if (bar) {
    var ticking = false;
    window.addEventListener("scroll", function () {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(function () {
        var h = document.documentElement;
        bar.style.width = (h.scrollTop / (h.scrollHeight - h.clientHeight || 1) * 100).toFixed(2) + "%";
        ticking = false;
      });
    }, { passive: true });
  }

  function countUp(el) {
    var target = parseInt(el.textContent, 10);
    if (reduce || isNaN(target)) return;
    el.textContent = "0";
    var n = 0, step = Math.max(1, Math.ceil(target / 26));
    var t = setInterval(function () {
      n += step;
      if (n >= target) { n = target; clearInterval(t); }
      el.textContent = String(n);
    }, 34);
  }

  document.querySelectorAll("[data-count]").forEach(function (el) {
    if (reduce) return;
    var seen = false;
    new IntersectionObserver(function (ents, obs) {
      ents.forEach(function (e) { if (e.isIntersecting && !seen) { seen = true; countUp(el); obs.disconnect(); } });
    }, { threshold: 1 }).observe(el);
  });

  var revealables = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window && !reduce) {
    var io = new IntersectionObserver(function (ents) {
      ents.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } });
    }, { threshold: 0.15, rootMargin: "0px 0px -6% 0px" });
    revealables.forEach(function (el) { io.observe(el); });
  } else {
    revealables.forEach(function (el) { el.classList.add("in"); });
  }

  var feed = document.getElementById("showFeed");
  if (feed) {
    var lines = [
      "recon mapped 12 origins, 47 subdomains",
      "phase 07 access control — testing IDOR",
      "IDOR proven on /api/orders/{id} · CVSS 9.1",
      "phase 08 injection — boolean-blind SQLi",
      "SQLi reproduced in sandbox, proof captured",
      "phase 09 XSS — reflected in attribute context",
      "reflected XSS proven · CWE-79",
      "phase 14 API — GraphQL introspection open",
      "report sealed — 6 findings, all reproduced"
    ];
    var i = 0;
    function add() {
      var t = new Date(Date.now() - (6 - (i % 6)) * 3000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
      var d = document.createElement("div");
      d.innerHTML = "<span class='t'>" + t + "</span> " + lines[i % lines.length];
      feed.appendChild(d);
      while (feed.children.length > 6) feed.removeChild(feed.children[1]);
      i++;
    }
    for (var k = 0; k < 5; k++) add();
    if (!reduce) setInterval(add, 2600);

    document.querySelectorAll("[data-mock]").forEach(function (el) {
      var seen = false;
      new IntersectionObserver(function (ents, obs) {
        ents.forEach(function (e) { if (e.isIntersecting && !seen) { seen = true; countUp(el); obs.disconnect(); } });
      }, { threshold: 0.4 }).observe(el);
    });
  }
})();
