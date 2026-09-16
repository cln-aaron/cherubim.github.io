(function () {
  "use strict";
  var d = document;
  var ly = d.getElementById("lyear");
  if (ly) ly.textContent = new Date().getFullYear();

  var HASH = "8337836b5b055f13d5d90c41d7cdbf0e3553300d2497d86106bd5a59c3f94454";
  var SALT = "cb1$";

  function sha256Hex(s) {
    var bytes = new TextEncoder().encode(s);
    return crypto.subtle.digest("SHA-256", bytes).then(function (buf) {
      var arr = new Uint8Array(buf), out = "";
      for (var i = 0; i < arr.length; i++) out += ("0" + arr[i].toString(16)).slice(-2);
      return out;
    });
  }

  function fail(msg) {
    var e = d.getElementById("authError");
    if (e) e.textContent = msg;
    var b = d.querySelector(".auth-btn");
    if (b) { b.textContent = "Enter the console"; b.classList.remove("loading"); }
  }

  function succeed(email) {
    try {
      sessionStorage.setItem("cb_s", "1");
      sessionStorage.setItem("cb_u", btoa(JSON.stringify({ name: "Aaron Ang", email: email, initials: "AA" })));
    } catch (e) {}
    var b = d.querySelector(".auth-btn");
    if (b) { b.textContent = "Authenticating…"; b.classList.add("loading"); }
    setTimeout(function () { location.href = "console/index.html"; }, 700);
  }

  function submit() {
    var email = (d.getElementById("email").value || "").trim().toLowerCase();
    var pass = d.getElementById("password").value || "";
    if (!email || !pass) { fail("Enter your email and password."); return; }
    if (!(crypto && crypto.subtle)) { fail("This browser is not supported."); return; }
    sha256Hex(SALT + email + ":" + pass).then(function (h) {
      if (h === HASH) { var e = d.getElementById("authError"); if (e) e.textContent = ""; succeed(email); }
      else fail("Those credentials are not recognised. Check and try again.");
    }).catch(function () { fail("Sign in failed. Try again."); });
  }

  var form = d.getElementById("loginForm");
  if (form) form.addEventListener("submit", function (e) { e.preventDefault(); submit(); });
})();
