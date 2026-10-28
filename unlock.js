const form=document.getElementById('unlock-form'),password=document.getElementById('password');
const button=document.getElementById('unlock'),status=document.getElementById('status');
const gate=document.getElementById('gate'),unlocked=document.getElementById('unlocked');
const content=document.getElementById('content'),lock=document.getElementById('lock');
const loading=document.getElementById('load-progress'),loadMessage=document.getElementById('load-message'),bar=document.getElementById('asset-progress');
const bytes=value=>Uint8Array.from(atob(value),char=>char.charCodeAt(0));
const urls=new Map();let generation=0,assetAbort;
const base=new URL('.',location.href);
const logical=path=>decodeURIComponent(new URL(path,base).pathname.slice(base.pathname.length));
function clear(){
  generation++;assetAbort?.abort();content.replaceChildren();delete window.lizAssets;
  for(const url of urls.values()) URL.revokeObjectURL(url);
  urls.clear();document.body.classList.remove('runtime');unlocked.hidden=true;gate.hidden=false;
  password.value='';loading.hidden=true;bar.value=0;
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
    let complete=false,assetsPending=true,lastReport=0,running=0;
    const waiting=[],requests=new Map(),parts=new Map(),received=new Map();
    const total=new Map(Object.values(app.assets).flatMap(asset=>asset.parts).map(part=>[part.url,part.size]));
    const totalBytes=[...total.values()].reduce((sum,size)=>sum+size,0);
    const progress=(force=false)=>{
      if(active!==generation || complete) return;
      const now=performance.now();if(!force && now-lastReport<80) return;lastReport=now;
      const loaded=[...received.values()].reduce((sum,size)=>sum+size,0);
      bar.value=totalBytes?loaded/totalBytes*100:0;
      const message=loaded===totalBytes?'下载完成，正在准备模型…':`下载素材 ${Math.floor(bar.value)}%（${(loaded/1048576).toFixed(1)} / ${(totalBytes/1048576).toFixed(1)} MB）`;
      status.textContent=loadMessage.textContent=message;
    };
    const fail=error=>{
      if(active!==generation) return;
      clear();status.textContent=error.message || '加载失败，请刷新重试';password.focus();
    };
    async function download(part){
      if(parts.has(part.url)) return parts.get(part.url);
      const promise=(async()=>{
        // ponytail: four requests bound memory and connection pressure for 16 MB blocks.
        if(running<4) running++;else await new Promise(resolve=>waiting.push(resolve));
        try {
          if(active!==generation) throw new Error('页面已锁定');
          if(!/^encrypted\/[a-f0-9]{64}\.bin$/.test(part.url) || bytes(part.iv).length!==12) throw new Error('素材记录无效');
          const response=await fetch(new URL(part.url,base),{cache:'force-cache',signal:controller.signal});
          if(!response.ok) throw new Error('素材读取失败，请刷新后重试');
          const data=new Uint8Array(part.size);let offset=0;
          const reader=response.body.getReader();
          while(true){
            const {done,value}=await reader.read();if(done) break;
            if(offset+value.length>data.length) throw new Error('素材大小异常');
            data.set(value,offset);offset+=value.length;received.set(part.url,offset);progress();
          }
          if(offset!==part.size) throw new Error('素材下载不完整，请刷新重试');
          progress(true);
          return await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(part.iv)},key,data);
        } finally {if(waiting.length) waiting.shift()();else running--;}
      })();
      parts.set(part.url,promise);return promise;
    }
    const cached=path=>{
      if(/^(blob:|data:)/.test(path)) return path;
      const url=urls.get(logical(path));
      if(!url) throw new Error('预览素材尚未就绪：'+logical(path));
      return url;
    };
    const get=path=>{
      if(active!==generation) return Promise.reject(new Error('页面已锁定'));
      const name=logical(path);
      if(urls.has(name)) return Promise.resolve(urls.get(name));
      if(requests.has(name)) return requests.get(name);
      const promise=(async()=>{
        const asset=app.assets[name];if(!asset) throw new Error('未知预览素材');
        const chunks=[];
        for(const part of asset.parts) chunks.push(await download(part));
        let blob=new Blob(chunks);
        if(asset.encoding==='gzip') blob=await new Response(blob.stream().pipeThrough(new DecompressionStream('gzip'))).blob();
        if(blob.size!==asset.size || active!==generation) throw new Error('素材读取中断');
        if(asset.type==='text/javascript') {
          const source=(await blob.text()).replace(/(from\s+)(['"])(\.\/[^'"]+)\2/g,(_,prefix,quote,path)=>prefix+quote+cached(new URL(path,new URL(name,base)).href)+quote);
          blob=new Blob([source],{type:asset.type});
        }
        if(active!==generation) throw new Error('页面已锁定');
        const url=URL.createObjectURL(new Blob([blob],{type:asset.type}));urls.set(name,url);return url;
      })();
      requests.set(name,promise);return promise;
    };
    const names=Object.keys(app.assets);
    const bootstrap=names.filter(name=>/\.(?:m?js|css|json)$/.test(name));
    // The workbench imports the head-texture and body-media modules.
    await Promise.all(bootstrap.filter(name=>name!=='art-workbench.mjs').map(get));
    await get('art-workbench.mjs');
    const assets=names.filter(name=>!bootstrap.includes(name));
    const downloads=assets.map(name=>({name,promise:get(name)}));
    const ready=Promise.all(downloads.filter(item=>!item.name.endsWith('.glb')).map(item=>item.promise)).catch(error=>{
      if(active!==generation) return new Promise(()=>{});
      throw error;
    });
    ready.catch(()=>{});
    window.lizAssets=Object.freeze({cached,get,ready,isDownloading:()=>assetsPending,
      complete(){if(active!==generation) return;complete=true;loading.hidden=true;status.textContent='工作台已就绪';parts.clear();requests.clear();},
      release(path){const name=logical(path);if(name.endsWith('.glb')){URL.revokeObjectURL(urls.get(name));urls.delete(name);requests.delete(name);}},
    });
    Promise.all(downloads.map(item=>item.promise)).then(()=>{assetsPending=false;progress(true);},fail);
    let html=app.html.replaceAll('__PAGE_BASE__',base.href);
    for(const [token,path] of [['__RIG_MODULE__','rig-submit.js'],['__PERFORMANCE_MODULE__','performance.mjs'],['__BREATHING_MODULE__','breathing.mjs'],['__DIALOGUE_CSS__','dialogue.css'],['__ART_CSS__','art-workbench.css']]) html=html.replaceAll(token,cached(path));
    const frame=document.createElement('iframe');frame.title='数字人美术预览';
    frame.setAttribute('sandbox','allow-scripts allow-same-origin allow-downloads');
    frame.srcdoc=html;content.replaceChildren(frame);
    gate.hidden=true;unlocked.hidden=false;loading.hidden=false;document.body.classList.add('runtime');progress(true);frame.focus();
  } catch(error){
    clear();status.textContent=error.message || '加载失败，请刷新重试';password.focus();
  } finally {button.disabled=false;}
});
lock.addEventListener('click',()=>{clear();status.textContent='已重新锁定。';password.focus();});
