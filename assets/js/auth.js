(function(){"use strict";
var d=document,ly=d.getElementById("lyear");if(ly)ly.textContent=new Date().getFullYear();
var g=d.getElementById("glow"),fine=window.matchMedia("(pointer:fine)").matches,rm=window.matchMedia("(prefers-reduced-motion: reduce)").matches;
if(g&&fine&&!rm){var ax=innerWidth/2,ay=innerHeight/2,bx=ax,by=ay;addEventListener("mousemove",function(e){ax=e.clientX;ay=e.clientY},{passive:true});(function l(){bx+=(ax-bx)*.12;by+=(ay-by)*.12;g.style.transform="translate("+bx+"px,"+by+"px) translate(-50%,-50%)";requestAnimationFrame(l)})();}else if(g){g.style.display="none";}
var K="8337836b5b055f13d5d90c41d7cdbf0e3553300d2497d86106bd5a59c3f94454",Z="cb1$";
function H(s){var b=new TextEncoder().encode(s);return crypto.subtle.digest("SHA-256",b).then(function(x){var a=new Uint8Array(x),o="",i;for(i=0;i<a.length;i++)o+=("0"+a[i].toString(16)).slice(-2);return o;});}
function err(m){var e=d.getElementById("authError");if(e)e.textContent=m;var b=d.querySelector(".auth-btn");if(b){b.textContent="Enter the console";b.classList.remove("loading");}}
function ok(em){try{sessionStorage.setItem("cb_s","1");sessionStorage.setItem("cb_u",btoa(JSON.stringify({name:"Aaron Ang",email:em,initials:"AA"})));}catch(e){}var b=d.querySelector(".auth-btn");if(b){b.textContent="Authenticating";b.classList.add("loading");}setTimeout(function(){location.href="console/index.html";},850);}
function go(){var e=(d.getElementById("email").value||"").trim().toLowerCase(),p=d.getElementById("password").value||"";if(!e||!p){err("Enter your email and password.");return;}
if(!(crypto&&crypto.subtle)){err("This browser is not supported.");return;}
H(Z+e+":"+p).then(function(h){if(h===K){var ee=d.getElementById("authError");if(ee)ee.textContent="";ok(e);}else err("Those credentials are not recognised. Check and try again.");}).catch(function(){err("Sign in failed. Try again.");});}
var f=d.getElementById("loginForm");if(f)f.addEventListener("submit",function(e){e.preventDefault();go();});
})();
