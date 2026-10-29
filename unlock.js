const form=document.getElementById('unlock-form'),password=document.getElementById('password');
const button=document.getElementById('unlock'),status=document.getElementById('status');
const gate=document.getElementById('gate'),unlocked=document.getElementById('unlocked');
const content=document.getElementById('content'),lock=document.getElementById('lock');
const loading=document.getElementById('load-progress'),loadMessage=document.getElementById('load-message'),bar=document.getElementById('asset-progress');
const bytes=value=>Uint8Array.from(atob(value),char=>char.charCodeAt(0));
const urls=new Map();let generation=0,assetAbort,cancelActiveTransfers;
const base=new URL('.',location.href);
const logical=path=>decodeURIComponent(new URL(path,base).pathname.slice(base.pathname.length));
function clear(){
  generation++;cancelActiveTransfers?.();cancelActiveTransfers=null;assetAbort?.abort();assetAbort=null;content.replaceChildren();delete window.lizAssets;
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
    let complete=false,lastReport=0,running=0;
    const waiting=[],requests=new Map(),parts=new Map(),received=new Map();
    const IDLE_TIMEOUT=45000;
    const locked=()=>active!==generation || controller.signal.aborted;
    const lockedError=()=>new Error('页面已锁定');
    const drainWaiting=error=>{while(waiting.length) waiting.shift().reject(error);};
    const cancelTransfers=()=>drainWaiting(lockedError());
    cancelActiveTransfers=cancelTransfers;
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
      const message=error?.message || '加载失败，请刷新重试';
      if(complete){status.textContent=loadMessage.textContent=message;loading.hidden=false;return;}
      clear();status.textContent=message;password.focus();
    };
    async function acquireSlot(){
      if(locked()) throw lockedError();
      if(running<4){running++;return;}
      await new Promise((resolve,reject)=>waiting.push({resolve:()=>{running++;resolve();},reject}));
      if(locked()){releaseSlot();throw lockedError();}
    }
    function releaseSlot(){
      running=Math.max(0,running-1);
      const waiter=waiting.shift();
      if(waiter) waiter.resolve();
    }
    async function fetchPart(part,cacheMode){
      if(locked()) throw lockedError();
      const attempt=new AbortController();
      let reader=null,timer=0,timedOut=false;
      const abort=()=>attempt.abort();
      const arm=()=>{clearTimeout(timer);timer=setTimeout(()=>{timedOut=true;attempt.abort();},IDLE_TIMEOUT);};
      controller.signal.addEventListener('abort',abort,{once:true});
      try {
        received.delete(part.url);arm();
        const response=await fetch(new URL(part.url,base),{cache:cacheMode,signal:attempt.signal});
        clearTimeout(timer);
        if(!response.ok) throw new Error('素材读取失败，请刷新后重试');
        if(!response.body) throw new Error('素材响应为空，请刷新后重试');
        reader=response.body.getReader();
        const data=new Uint8Array(part.size);let offset=0;
        while(true){
          arm();
          let result;
          try {result=await reader.read();} finally {clearTimeout(timer);}
          const {done,value}=result;if(done) break;
          if(offset+value.length>data.length) throw new Error('素材大小异常');
          data.set(value,offset);offset+=value.length;received.set(part.url,offset);progress();
        }
        if(offset!==part.size) throw new Error('素材下载不完整，请刷新重试');
        progress(true);
        return await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(part.iv)},key,data);
      } catch(error){
        if(locked()) throw lockedError();
        if(timedOut) throw new Error('素材读取超时，请刷新重试');
        throw error;
      } finally {
        clearTimeout(timer);controller.signal.removeEventListener('abort',abort);
        try {await reader?.cancel?.();} catch (_) {}
        try {reader?.releaseLock?.();} catch (_) {}
      }
    }
    async function download(part){
      if(parts.has(part.url)) return parts.get(part.url);
      if(!/^encrypted\/[a-f0-9]{64}\.bin$/.test(part.url) || bytes(part.iv).length!==12) throw new Error('素材记录无效');
      const promise=(async()=>{
        let acquired=false;
        try {
          await acquireSlot();acquired=true;
          let failure;
          for(const cacheMode of ['force-cache','reload']){
            try {return await fetchPart(part,cacheMode);}
            catch(error){
              if(locked()) throw error;
              failure=error;
            }
          }
          throw failure || new Error('素材读取失败，请刷新后重试');
        } finally {if(acquired) releaseSlot();}
      })();
      parts.set(part.url,promise);
      promise.catch(()=>{if(parts.get(part.url)===promise) parts.delete(part.url);});
      return promise;
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
        // ponytail: consume one block at a time; retaining all decrypted buffers doubles model memory.
        let index=0;
        let stream=new ReadableStream({async pull(streamController){
          if(index===asset.parts.length){streamController.close();return;}
          const part=asset.parts[index++];
          try {streamController.enqueue(new Uint8Array(await download(part)));}
          catch(error){streamController.error(error);}
          finally {parts.delete(part.url);}
        }});
        if(asset.encoding==='gzip') stream=stream.pipeThrough(new DecompressionStream('gzip'));
        let blob=await new Response(stream).blob();
        if(blob.size!==asset.size || active!==generation) throw new Error('素材读取中断');
        if(asset.type==='text/javascript') {
          const source=(await blob.text()).replace(/(from\s+)(['"])(\.\/[^'"]+)\2/g,(_,prefix,quote,path)=>prefix+quote+cached(new URL(path,new URL(name,base)).href)+quote);
          blob=new Blob([source],{type:asset.type});
        }
        if(active!==generation) throw new Error('页面已锁定');
        const url=URL.createObjectURL(new Blob([blob],{type:asset.type}));urls.set(name,url);return url;
      })();
      requests.set(name,promise);
      promise.then(()=>requests.delete(name),error=>{requests.delete(name);fail(error);});
      return promise;
    };
    const names=Object.keys(app.assets);
    const bootstrap=names.filter(name=>/\.(?:m?js|css|json)$/.test(name));
    // The workbench imports the head-texture and body-media modules.
    await Promise.all(bootstrap.filter(name=>name!=='art-workbench.mjs').map(get));
    await get('art-workbench.mjs');
    const assets=names.filter(name=>!bootstrap.includes(name));
    // Models are requested by the renderer in parse order, so head and hair do not peak together.
    const downloads=assets.filter(name=>!name.endsWith('.glb')).map(name=>get(name));
    const ready=Promise.all(downloads).catch(error=>{
      if(active!==generation) return new Promise(()=>{});
      throw error;
    });
    ready.catch(()=>{});
    window.lizAssets=Object.freeze({cached,get,ready,fail,isDownloading:()=>running>0 || waiting.length>0,
      complete(){if(active!==generation) return;complete=true;loading.hidden=true;status.textContent='工作台已就绪';parts.clear();requests.clear();},
      release(path){
        if(typeof path!=='string' || /^(blob:|data:)/.test(path)) return;
        const name=logical(path);if(!name.endsWith('.glb')) return;
        const url=urls.get(name);if(url){URL.revokeObjectURL(url);urls.delete(name);}
        requests.delete(name);for(const part of app.assets[name]?.parts || []) parts.delete(part.url);
      },
    });
    ready.then(()=>progress(true),fail);
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
