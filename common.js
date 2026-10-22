'use strict';
const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let session={user:null,csrf:null};
async function api(path,data){const options={credentials:'same-origin',headers:{}};if(data!==undefined){options.method='POST';options.headers={'Content-Type':'application/json','X-CSRF-Token':session.csrf||''};options.body=JSON.stringify(data)}const r=await fetch(path,options);let result;try{result=await r.json()}catch{throw Error('Réponse serveur invalide.')}if(!r.ok)throw Error(result.error||'Une erreur est survenue.');return result}
function toast(message,error=false){let el=$('#toast');el.textContent=message;el.classList.toggle('error',error);el.hidden=false;clearTimeout(window.toastTimeout);window.toastTimeout=setTimeout(()=>el.hidden=true,5000)}
function openDialog(html){$('#modal').innerHTML=html;const d=$('dialog');if(!d.open)d.showModal()}
function closeDialog(){$('dialog').close()}
$('.close').onclick=closeDialog;
function formatSize(n){return !n?'Aucun fichier':n<1048576?(n/1024).toFixed(1)+' Ko':(n/1048576).toFixed(1)+' Mo'}
function date(n){return new Date(n*1000).toLocaleString('fr-FR')}
async function logout(){await api('/api/logout',{});location.href='/'}
window.addEventListener('unhandledrejection',e=>{toast(e.reason?.message||'Erreur de connexion.',true);e.preventDefault()});
