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

  var VALID_EMAIL = "aaron@hesedemet.asia";
  var VALID_PASS = "P@ssw0rd!P@ssw0rd!";
  var USER = { name: "Aaron Ang", email: VALID_EMAIL, initials: "AA" };

  function fail(msg) {
    var e = document.getElementById("authError");
    if (e) e.textContent = msg;
    var btn = document.querySelector(".auth-btn");
    if (btn) { btn.textContent = "Enter the console"; btn.classList.remove("loading"); }
  }

  function submit() {
    var email = (document.getElementById("email").value || "").trim().toLowerCase();
    var pass = document.getElementById("password").value || "";
    if (!email || !pass) { fail("Enter your email and password."); return; }
    if (email !== VALID_EMAIL || pass !== VALID_PASS) {
      fail("Those credentials are not recognised. Check and try again.");
      return;
    }
    try {
      sessionStorage.setItem("cherubim_auth", "1");
      sessionStorage.setItem("cherubim_user", JSON.stringify(USER));
    } catch (e) {}
    var err = document.getElementById("authError");
    if (err) err.textContent = "";
    var btn = document.querySelector(".auth-btn");
    if (btn) { btn.textContent = "Authenticating"; btn.classList.add("loading"); }
    setTimeout(function () { location.href = "console/index.html"; }, 850);
  }

  var form = document.getElementById("loginForm");
  if (form) form.addEventListener("submit", function (e) { e.preventDefault(); submit(); });
})();
