"use strict";
(() => {
  const button=document.getElementById('motion-toggle');
  const plane=document.querySelector('.night-sky-parallax');
  const texture=document.querySelector('.night-sky-flow');
  if(!button||!plane||!texture)return;
  const reduced=matchMedia('(prefers-reduced-motion: reduce)');
  let enabled=!reduced.matches,pending=false;
  function updatePosition(){
    if(pending||!enabled||reduced.matches||document.hidden)return;
    pending=true;
    requestAnimationFrame(()=>{
      pending=false;
      if(!enabled||reduced.matches||document.hidden)return;
      const tile=parseFloat(getComputedStyle(texture).backgroundSize)||Math.max(900,innerWidth);
      const shift=-((Math.max(0,scrollY)*.12)%tile);
      plane.style.transform='translate3d(0,'+shift.toFixed(2)+'px,0)';
    });
  }
  function sync(){
    const active=enabled&&!reduced.matches;
    document.body.classList.toggle('motion-paused',!active);
    button.setAttribute('aria-pressed',String(active));button.disabled=reduced.matches;
    button.setAttribute('aria-label',active?'Остановить анимацию фона':'Включить анимацию фона');
    if(active)updatePosition();
  }
  button.addEventListener('click',()=>{enabled=!enabled;sync();});
  reduced.addEventListener('change',()=>{if(reduced.matches)enabled=false;sync();});
  addEventListener('scroll',updatePosition,{passive:true});addEventListener('resize',updatePosition,{passive:true});
  document.addEventListener('visibilitychange',()=>{
    document.body.classList.toggle('motion-paused',document.hidden||!enabled||reduced.matches);
    if(!document.hidden)updatePosition();
  });
  sync();
})();
