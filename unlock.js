const form=document.getElementById('unlock-form'),password=document.getElementById('password');
const button=document.getElementById('unlock'),status=document.getElementById('status');
const gate=document.getElementById('gate'),unlocked=document.getElementById('unlocked');
const content=document.getElementById('content'),lock=document.getElementById('lock');
const bytes=value=>Uint8Array.from(atob(value),char=>char.charCodeAt(0));
const urls=new Map();let generation=0,assetAbort;
const base=new URL('.',location.href);
const logical=path=>decodeURIComponent(new URL(path,base).pathname.slice(base.pathname.length));
function clear(){
  generation++;assetAbort?.abort();content.replaceChildren();delete window.lizAssets;
  for(const url of urls.values()) URL.revokeObjectURL(url);
  urls.clear();document.body.classList.remove('runtime');unlocked.hidden=true;gate.hidden=false;
  password.value='';
}
form.addEventListener('submit',async event=>{
  event.preventDefault();if(!password.value || button.disabled) return;
  if(!crypto?.subtle || !globalThis.DecompressionStream){status.textContent='请使用新版 Chrome、Edge 或 Safari，通过 HTTPS 打开。';return;}
  button.disabled=true;status.textContent='正在解锁…';
  const active=++generation;
  const controller=new AbortController();assetAbort=controller;
  try {
    const response=await fetch('./content.enc.json',{cache:'no-store',signal:controller.signal});
    if(!response.ok) throw new Error('页面资源读取失败');
    const envelope=await response.json();
    if(envelope.version!==2 || envelope.kdf!=='PBKDF2-SHA-256' || envelope.iterations!==600000 || bytes(envelope.salt).length!==16 || bytes(envelope.iv).length!==12) throw new Error('页面版本异常，请刷新');
    const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password.value),'PBKDF2',false,['deriveKey']);
    const key=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:bytes(envelope.salt),iterations:envelope.iterations},material,{name:'AES-GCM',length:256},false,['decrypt']);
    let raw;
    try {raw=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(envelope.iv)},key,bytes(envelope.ciphertext));}
    catch {throw new Error('密码不正确，请重新输入');}
    password.value='';
    const app=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
    if(app.format!=='liz-art-app' || app.version!==1 || !app.assets || typeof app.html!=='string') throw new Error('预览版本无效');
    const progress=message=>{
      if(active!==generation) return;
      status.textContent=message;
      const label=content.querySelector('iframe')?.contentDocument?.getElementById('loading');
      if(label){label.style.display='flex';label.textContent=message;}
    };
    const cached=path=>{
      if(/^(blob:|data:)/.test(path)) return path;
      const url=urls.get(logical(path));
      if(!url) throw new Error('预览素材尚未就绪：'+logical(path));
      return url;
    };
    const get=async path=>{
      const name=logical(path);if(urls.has(name)) return urls.get(name);
      const asset=app.assets[name];if(!asset) throw new Error('未知预览素材');
      const chunks=[];let loaded=0;
      const total=asset.parts.reduce((sum,part)=>sum+part.size,0);
      const label=name.endsWith('.glb')?(name.includes('hair-')?'头发':'头模'):'画面素材';
      for(const part of asset.parts){
        if(active!==generation) throw new Error('页面已锁定');
        if(!/^encrypted\/[a-f0-9]{64}\.bin$/.test(part.url) || bytes(part.iv).length!==12) throw new Error('素材记录无效');
        progress(`正在加载${label} ${Math.round(loaded/total*100)}%（${Math.round(total/1048576)} MB）`);
        const file=await fetch(new URL(part.url,base),{cache:'force-cache',signal:controller.signal});
        if(!file.ok) throw new Error('素材读取失败，请刷新后重试');
        chunks.push(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(part.iv)},key,await file.arrayBuffer()));
        loaded+=part.size;
      }
      progress(`正在准备${label}…`);
      let blob=new Blob(chunks);
      if(asset.encoding==='gzip') blob=await new Response(blob.stream().pipeThrough(new DecompressionStream('gzip'))).blob();
      if(blob.size!==asset.size || active!==generation) throw new Error('素材读取中断');
      const url=URL.createObjectURL(new Blob([blob],{type:asset.type}));urls.set(name,url);return url;
    };
    window.lizAssets=Object.freeze({cached,get,release(path){const name=logical(path);if(name.endsWith('.glb')){URL.revokeObjectURL(urls.get(name));urls.delete(name);}}});
    // ponytail: textures and three small modules first; the two GLBs load in sequence inside the renderer.
    for(const name of Object.keys(app.assets)) if(!name.endsWith('.glb')) await get(name);
    let html=app.html.replaceAll('__PAGE_BASE__',base.href);
    for(const [token,path] of [['__RIG_MODULE__','rig-submit.js'],['__PERFORMANCE_MODULE__','performance.mjs'],['__BREATHING_MODULE__','breathing.mjs']]) html=html.replaceAll(token,cached(path));
    const frame=document.createElement('iframe');frame.title='数字人美术预览';
    frame.setAttribute('sandbox','allow-scripts allow-same-origin allow-downloads');
    frame.srcdoc=html;content.replaceChildren(frame);
    gate.hidden=true;unlocked.hidden=false;document.body.classList.add('runtime');frame.focus();
  } catch(error){
    clear();status.textContent=error.message || '加载失败，请刷新重试';password.focus();
  } finally {button.disabled=false;}
});
lock.addEventListener('click',()=>{clear();status.textContent='已重新锁定。';password.focus();});
