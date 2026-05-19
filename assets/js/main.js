(function () {
  "use strict";

  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Year
  var y = document.getElementById("year");
  if (y) y.textContent = "© " + new Date().getFullYear();

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
})();
