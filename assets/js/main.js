(function () {
  "use strict";

  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Year
  var y = document.getElementById("year");
  if (y) y.textContent = new Date().getFullYear();

  // Mobile nav
  var nav = document.getElementById("nav");
  var toggle = document.getElementById("navToggle");
  if (toggle && nav) {
    toggle.addEventListener("click", function () {
      var open = nav.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    nav.querySelectorAll(".nav-links a").forEach(function (a) {
      a.addEventListener("click", function () {
        nav.classList.remove("open");
        toggle.setAttribute("aria-expanded", "false");
      });
    });
  }

  // Scroll progress bar
  var bar = document.getElementById("progress");
  if (bar) {
    var tick = false;
    window.addEventListener("scroll", function () {
      if (tick) return;
      tick = true;
      requestAnimationFrame(function () {
        var h = document.documentElement;
        var p = h.scrollTop / (h.scrollHeight - h.clientHeight || 1);
        bar.style.width = (p * 100).toFixed(2) + "%";
        tick = false;
      });
    }, { passive: true });
  }

  // Cursor glow
  var glow = document.getElementById("glow");
  if (glow && !reduce && window.matchMedia("(pointer:fine)").matches) {
    var gx = window.innerWidth / 2, gy = window.innerHeight / 2, cx = gx, cy = gy;
    window.addEventListener("mousemove", function (e) { gx = e.clientX; gy = e.clientY; }, { passive: true });
    (function loop() {
      cx += (gx - cx) * 0.12;
      cy += (gy - cy) * 0.12;
      glow.style.transform = "translate(" + cx + "px," + cy + "px) translate(-50%,-50%)";
      requestAnimationFrame(loop);
    })();
  } else if (glow) {
    glow.style.display = "none";
  }

  // Kinetic hero reveal
  var kinetic = document.querySelector(".kinetic");
  if (kinetic) {
    if (reduce) kinetic.classList.add("in");
    else requestAnimationFrame(function () {
      setTimeout(function () { kinetic.classList.add("in"); }, 120);
    });
  }

  // Count-up stats
  document.querySelectorAll("[data-count]").forEach(function (el) {
    var target = parseInt(el.textContent, 10);
    if (reduce || isNaN(target)) return;
    el.textContent = "0";
    var seen = false;
    var ob = new IntersectionObserver(function (en) {
      en.forEach(function (e) {
        if (!e.isIntersecting || seen) return;
        seen = true;
        var n = 0, step = Math.max(1, Math.ceil(target / 26));
        var t = setInterval(function () {
          n += step;
          if (n >= target) { n = target; clearInterval(t); }
          el.textContent = String(n);
        }, 32);
      });
    }, { threshold: 1 });
    ob.observe(el);
  });

  // Scroll reveal
  var targets = document.querySelectorAll(
    ".sec-head, .card, .split-copy, .split-visual, .channel, .compare-col, .arch-item, .outcomes div, .faq details, .cta-inner, .strip-inner, .orchestration"
  );
  targets.forEach(function (el) { el.classList.add("reveal"); });

  if ("IntersectionObserver" in window && !reduce) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
      });
    }, { threshold: 0.12, rootMargin: "0px 0px -8% 0px" });
    targets.forEach(function (el) { io.observe(el); });
  } else {
    targets.forEach(function (el) { el.classList.add("in"); });
  }

  // Product showcase animation
  var feed = document.getElementById("showFeed");
  if (feed) {
    var lines = [
      "agent.recon mapped 1,284 assets",
      "agent.web proved logic bypass on payments",
      "validator reproduced F-3303 (3x)",
      "agent.identity recovered CI credential",
      "agent.cloud assumed node role via IMDS",
      "narrative.engine escalated vishing scenario",
      "agent.privesc reached Domain Admin, stopped",
      "compliance.map tagged finding to NIST",
      "coach delivered a 3 min lesson on Teams"
    ];
    var fi = 0;
    function feedAdd() {
      var t = new Date(Date.now() - (6 - (fi % 6)) * 3000)
        .toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
      var d = document.createElement("div");
      d.innerHTML = "<span class='t'>" + t + "</span> " + lines[fi % lines.length];
      feed.insertBefore(d, feed.firstChild);
      while (feed.children.length > 7) feed.removeChild(feed.lastChild);
      fi++;
    }
    for (var k = 0; k < 6; k++) feedAdd();
    if (!reduce) setInterval(feedAdd, 2600);

    var mocks = document.querySelectorAll("[data-mock]");
    var ran = false;
    function runCount() {
      if (ran) return; ran = true;
      mocks.forEach(function (el) {
        var target = parseInt(el.textContent, 10); if (isNaN(target)) return;
        if (reduce) return;
        var n = 0, step = Math.max(1, Math.ceil(target / 24));
        el.textContent = "0";
        var t = setInterval(function () {
          n += step; if (n >= target) { n = target; clearInterval(t); }
          el.textContent = String(n);
        }, 34);
      });
    }
    if ("IntersectionObserver" in window) {
      var so = new IntersectionObserver(function (en) {
        en.forEach(function (e) { if (e.isIntersecting) { runCount(); so.disconnect(); } });
      }, { threshold: 0.3 });
      so.observe(feed);
    } else { runCount(); }
  }
})();
