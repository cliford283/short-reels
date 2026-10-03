

loadPublicAds();

if(!window.DH_AD_MUTATION_OBSERVER){
  const appEl = document.getElementById('app');

  if(appEl){
    window.DH_AD_MUTATION_OBSERVER = new MutationObserver(()=>{
      trackVisibleAds();
    });

    window.DH_AD_MUTATION_OBSERVER.observe(appEl,{
      childList:true,
      subtree:true
    });

    trackVisibleAds();
  }
}


window.addEventListener('load', function(){
  if (typeof syncPublicEpisodes === 'function') {

    // Do not block the first page render while episodes are loading.
    // Render the current route immediately.
    if (typeof location !== 'undefined' && location.hash) {
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    }

    // Load episode data in the background.
    syncPublicEpisodes().then(function(){
      if (typeof location !== 'undefined' && location.hash) {
        window.dispatchEvent(new HashChangeEvent('hashchange'));
      }
    }).catch(function(e){
      console.log('Background episode sync failed:', e);
    });

    setInterval(async function(){
      const before = JSON.stringify(PUBLIC_EPISODES);

      await syncPublicEpisodes();

      const after = JSON.stringify(PUBLIC_EPISODES);

      if (before !== after && typeof location !== 'undefined' && location.hash) {
        window.dispatchEvent(new HashChangeEvent('hashchange'));
      }
    }, 30000);
  }
});

;

(function(){
  const notice = document.getElementById('sr-cookie-consent-v2');
  const accept = document.getElementById('sr-cookie-accept-v2');

  if (!notice || !accept) return;

  const KEY = 'sr_cookie_consent_v2';

  try {
    if (localStorage.getItem(KEY) === '1') {
      notice.remove();
      return;
    }
  } catch (_) {}

  notice.style.display = 'block';

  accept.addEventListener('click', function(){
    try {
      localStorage.setItem(KEY, '1');
    } catch (_) {}

    notice.remove();
  });
})();








/* ===== ANDROID REELS FULLSCREEN ===== */
(function(){

  let reelsFullscreen=false;

  function isEpisodePage(){
    const [route] = (location.hash.slice(2) || 'home').split('/');
    return (
      (route === 'watch' || route === 'episode') &&
      !!document.querySelector('.pl')
    );
  }

  function lockPage(){
    const active = isEpisodePage();
    document.documentElement.classList.toggle(
      'dh-reels-fullscreen',
      active
    );
    return active;
  }

  let lastRoute = location.hash;

  setInterval(function(){
    if(location.hash === lastRoute) return;

    lastRoute = location.hash;

    if(isEpisodePage()){
      lockPage();
    }else{
      document.documentElement.classList.remove('dh-reels-fullscreen');
    }
  },250);

  lockPage();

})();

