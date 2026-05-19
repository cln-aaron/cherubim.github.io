(function () {
  "use strict";

  var ly = document.getElementById("lyear");
  if (ly) ly.textContent = new Date().getFullYear();

  // Cursor glow (shared behaviour)
  var glow = document.getElementById("glow");
  if (glow && window.matchMedia("(pointer:fine)").matches &&
      !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    var gx = innerWidth / 2, gy = innerHeight / 2, cx = gx, cy = gy;
    addEventListener("mousemove", function (e) { gx = e.clientX; gy = e.clientY; }, { passive: true });
    (function loop() {
      cx += (gx - cx) * 0.12; cy += (gy - cy) * 0.12;
      glow.style.transform = "translate(" + cx + "px," + cy + "px) translate(-50%,-50%)";
      requestAnimationFrame(loop);
    })();
  } else if (glow) { glow.style.display = "none"; }

  function enter() {
    try { sessionStorage.setItem("cherubim_demo", "1"); } catch (e) {}
    var btn = document.querySelector(".auth-btn");
    if (btn) { btn.textContent = "Authenticating"; btn.classList.add("loading"); }
    setTimeout(function () { location.href = "demo/index.html"; }, 850);
  }

  var form = document.getElementById("loginForm");
  if (form) form.addEventListener("submit", function (e) { e.preventDefault(); enter(); });
  var sso = document.getElementById("ssoBtn");
  if (sso) sso.addEventListener("click", enter);
})();
