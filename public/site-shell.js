// Local navigation only. Authentication and each panel's internal permissions
// remain owned by their existing modules; no data or credentials are copied.
const names=['watchdogs','archive'];
const panels=new Map(names.map(name=>[name,document.getElementById(name+'-panel')]));
const links=new Map(names.map(name=>[name,document.getElementById(name+'-tab')]));
function showPanel(){
 const active=location.hash==='#archive'?'archive':'watchdogs';
 for(const name of names){
  const panel=panels.get(name),link=links.get(name);
  if(name===active){panel.hidden=false;link.setAttribute('aria-current','page');}
  else{
   if(panel.contains(document.activeElement))links.get(active).focus();
   panel.hidden=true;link.removeAttribute('aria-current');
  }
 }
}
window.addEventListener('hashchange',showPanel);
showPanel();
