const form=document.getElementById('unlock-form');
const password=document.getElementById('password');
const button=document.getElementById('unlock');
const status=document.getElementById('status');
const gate=document.getElementById('gate');
const unlocked=document.getElementById('unlocked');
const content=document.getElementById('content');
const lock=document.getElementById('lock');
const bytes=value=>Uint8Array.from(atob(value),char=>char.charCodeAt(0));
let envelope;
form.addEventListener('submit',async event=>{
  event.preventDefault();
  if(!password.value || button.disabled) return;
  if(!globalThis.crypto?.subtle){status.textContent='请通过 HTTPS 在新版浏览器中打开。';return;}
  button.disabled=true;
  status.textContent='正在解锁…';
  try {
    if(!envelope){
      const response=await fetch('./content.enc.json',{cache:'no-store'});
      if(!response.ok) throw new Error('resource');
      envelope=await response.json();
      if(envelope.version!==1 || envelope.kdf!=='PBKDF2-SHA-256' || envelope.iterations!==600000 || bytes(envelope.salt).length!==16 || bytes(envelope.iv).length!==12) throw new Error('resource');
    }
    const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password.value),'PBKDF2',false,['deriveKey']);
    const key=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:bytes(envelope.salt),iterations:envelope.iterations},material,{name:'AES-GCM',length:256},false,['decrypt']);
    const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(envelope.iv)},key,bytes(envelope.ciphertext));
    // The authenticated payload is built locally; no visitor input becomes HTML.
    content.innerHTML=new TextDecoder('utf-8',{fatal:true}).decode(plaintext);
    const address=document.createElement('p');
    address.className='address';
    address.textContent='当前网址：'+location.href;
    content.append(address);
    password.value='';
    status.textContent='';
    gate.hidden=true;
    unlocked.hidden=false;
    lock.focus();
  } catch(error) {
    status.textContent=error.message==='resource' || error instanceof TypeError ? '页面资源读取失败，请刷新后重试。' : '密码不正确，请重新输入。';
    password.focus();
  } finally {button.disabled=false;}
});
lock.addEventListener('click',()=>{
  content.replaceChildren();
  unlocked.hidden=true;
  gate.hidden=false;
  password.value='';
  status.textContent='已重新锁定。';
  password.focus();
});
