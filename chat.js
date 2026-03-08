/**
 * IRS Financial Calculator - Team Chat
 * Loads socket.io.min.js first, then initialises the chat UI.
 */
(function () {
  'use strict';

  // Wait until socket.io client is loaded, then boot
  function loadSocketIO(cb) {
    if (window.io) { cb(); return; }
    const s = document.createElement('script');
    s.src = '/socket.io.min.js';
    s.onload = cb;
    s.onerror = function () { console.error('[Chat] Could not load socket.io client'); };
    document.head.appendChild(s);
  }

  function tryInit() {
    const token  = sessionStorage.getItem('irs_token');
    const myName = sessionStorage.getItem('irs_username');
    if (!token || !myName) {
      // Session not set yet - poll until it is (covers pages that set token after load)
      let attempts = 0;
      const poll = setInterval(function () {
        attempts++;
        const t = sessionStorage.getItem('irs_token');
        const n = sessionStorage.getItem('irs_username');
        if (t && n) { clearInterval(poll); loadSocketIO(function () { run(t, n); }); }
        if (attempts > 60) clearInterval(poll);
      }, 500);
      return;
    }
    loadSocketIO(function () { run(token, myName); });
  }

  function run(token, myName) {

    //  CSS 
    const style = document.createElement('style');
    style.textContent = `
      #irs-chat-fab {
        position:fixed;bottom:24px;right:24px;z-index:9998;
        width:56px;height:56px;border-radius:50%;
        background:linear-gradient(135deg,#5D5CDE,#3498db);
        border:none;cursor:pointer;
        box-shadow:0 4px 18px rgba(93,92,222,.55);
        display:flex;align-items:center;justify-content:center;
        transition:transform .2s,box-shadow .2s;
      }
      #irs-chat-fab:hover{transform:scale(1.1);}
      #irs-chat-fab svg{width:28px;height:28px;fill:#fff;}
      #irs-chat-badge{
        position:absolute;top:-2px;right:-2px;
        background:#ef4444;color:#fff;border-radius:50%;
        width:19px;height:19px;font-size:10px;font-weight:700;
        display:none;align-items:center;justify-content:center;
        border:2px solid #fff;pointer-events:none;
      }
      #irs-chat-badge.show{display:flex;}
      #irs-chat-panel{
        position:fixed;bottom:90px;right:24px;z-index:9999;
        width:360px;height:520px;max-height:calc(100vh - 120px);
        background:#fff;border-radius:16px;
        box-shadow:0 12px 48px rgba(0,0,0,.22);
        display:flex;flex-direction:column;overflow:hidden;
        opacity:0;pointer-events:none;
        transform:translateY(16px) scale(.97);
        transition:opacity .2s,transform .2s;
      }
      #irs-chat-panel.open{opacity:1;pointer-events:all;transform:none;}
      #irs-chat-header{
        background:linear-gradient(135deg,#5D5CDE,#3498db);
        padding:14px 16px;color:#fff;
        display:flex;align-items:center;justify-content:space-between;flex-shrink:0;
      }
      #irs-chat-header h3{font-size:.95rem;font-weight:700;margin:0;}
      #irs-chat-header small{font-size:.75rem;opacity:.85;}
      #irs-chat-close{
        background:rgba(255,255,255,.2);border:none;color:#fff;
        border-radius:50%;width:28px;height:28px;cursor:pointer;
        font-size:1rem;display:flex;align-items:center;justify-content:center;
      }
      #irs-chat-online-bar{
        padding:6px 12px;background:#f8f9ff;border-bottom:1px solid #eee;
        font-size:.75rem;color:#555;flex-shrink:0;
        white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
      }
      .irs-dot{display:inline-block;width:7px;height:7px;
        background:#22c55e;border-radius:50%;margin-right:4px;}
      #irs-chat-messages{
        flex:1;overflow-y:auto;padding:12px;
        display:flex;flex-direction:column;gap:8px;
      }
      #irs-chat-messages::-webkit-scrollbar{width:4px;}
      #irs-chat-messages::-webkit-scrollbar-thumb{background:#ddd;border-radius:4px;}
      .im{display:flex;flex-direction:column;max-width:82%;}
      .im.me{align-self:flex-end;align-items:flex-end;}
      .im.other{align-self:flex-start;align-items:flex-start;}
      .im-meta{font-size:.68rem;color:#999;margin-bottom:2px;}
      .im.me .im-meta{color:#7c7ce0;}
      .im-bubble{
        padding:8px 12px;border-radius:14px;font-size:.875rem;
        line-height:1.4;word-break:break-word;
      }
      .im.me .im-bubble{
        background:linear-gradient(135deg,#5D5CDE,#3498db);
        color:#fff;border-bottom-right-radius:4px;
      }
      .im.other .im-bubble{
        background:#f0f0f8;color:#333;border-bottom-left-radius:4px;
      }
      #irs-chat-typing{
        padding:4px 12px;font-size:.72rem;color:#999;
        flex-shrink:0;min-height:20px;font-style:italic;
      }
      #irs-chat-input-row{
        padding:10px 12px;border-top:1px solid #eee;flex-shrink:0;
        display:flex;gap:8px;align-items:center;background:#fafafa;
      }
      #irs-chat-input{
        flex:1;border:1.5px solid #e0e0e0;border-radius:20px;
        padding:8px 14px;font-size:.875rem;outline:none;background:#fff;
        transition:border-color .2s;
      }
      #irs-chat-input:focus{border-color:#5D5CDE;}
      #irs-chat-send{
        width:36px;height:36px;border-radius:50%;border:none;
        background:linear-gradient(135deg,#5D5CDE,#3498db);
        color:#fff;cursor:pointer;flex-shrink:0;
        display:flex;align-items:center;justify-content:center;
      }
      #irs-chat-send:hover{filter:brightness(1.1);}
      #irs-chat-send svg{width:16px;height:16px;fill:#fff;}
      .idate{text-align:center;font-size:.68rem;color:#bbb;margin:4px 0;}
      @media(max-width:420px){
        #irs-chat-panel{width:calc(100vw - 20px);right:10px;}
      }
    `;
    document.head.appendChild(style);

    //  HTML 
    const wrap = document.createElement('div');
    wrap.innerHTML = `
      <button id="irs-chat-fab" title="Team Chat">
        <svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2z"/></svg>
        <span id="irs-chat-badge"></span>
      </button>
      <div id="irs-chat-panel">
        <div id="irs-chat-header">
          <div>
            <h3>&#x1F4AC; Team Chat</h3>
            <small id="irs-chat-sub">Connecting&hellip;</small>
          </div>
          <button id="irs-chat-close">&#x2715;</button>
        </div>
        <div id="irs-chat-online-bar"><span class="irs-dot"></span>Connecting&hellip;</div>
        <div id="irs-chat-messages"></div>
        <div id="irs-chat-typing"></div>
        <div id="irs-chat-input-row">
          <input id="irs-chat-input" type="text" placeholder="Type a message&hellip;" maxlength="1000" autocomplete="off">
          <button id="irs-chat-send" title="Send">
            <svg viewBox="0 0 24 24"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg>
          </button>
        </div>
      </div>`;
    document.body.appendChild(wrap);

    //  Refs 
    const fab      = document.getElementById('irs-chat-fab');
    const panel    = document.getElementById('irs-chat-panel');
    const badge    = document.getElementById('irs-chat-badge');
    const onlineEl = document.getElementById('irs-chat-online-bar');
    const subEl    = document.getElementById('irs-chat-sub');
    const msgsEl   = document.getElementById('irs-chat-messages');
    const typingEl = document.getElementById('irs-chat-typing');
    const inputEl  = document.getElementById('irs-chat-input');

    var isOpen = false, unread = 0, typingTimer = null, lastDate = null;

    //  Utils 
    function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
    function fmtTime(ts) { return new Date(ts*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}); }
    function fmtDate(ts) {
      var d=new Date(ts*1000), t=new Date();
      if(d.toDateString()===t.toDateString()) return 'Today';
      var y=new Date(); y.setDate(y.getDate()-1);
      if(d.toDateString()===y.toDateString()) return 'Yesterday';
      return d.toLocaleDateString([],{month:'short',day:'numeric'});
    }

    function scrollBottom(force) {
      var atBottom = msgsEl.scrollHeight - msgsEl.scrollTop - msgsEl.clientHeight < 120;
      if(force||atBottom) setTimeout(function(){ msgsEl.scrollTop=msgsEl.scrollHeight; },30);
    }

    function renderMsg(msg) {
      var dl = fmtDate(msg.created_at);
      if(dl !== lastDate) {
        lastDate = dl;
        var div = document.createElement('div');
        div.className = 'idate';
        div.textContent = dl;
        msgsEl.appendChild(div);
      }
      var me = msg.username === myName;
      var el = document.createElement('div');
      el.className = 'im ' + (me ? 'me' : 'other');
      el.innerHTML = '<div class="im-meta">' + (me ? 'You' : esc(msg.username)) + ' &middot; ' + fmtTime(msg.created_at) + '</div>' +
                     '<div class="im-bubble">' + esc(msg.message) + '</div>';
      msgsEl.appendChild(el);
    }

    //  Toggle 
    fab.addEventListener('click', function() {
      isOpen = !isOpen;
      panel.classList.toggle('open', isOpen);
      if(isOpen) {
        unread=0; badge.textContent=''; badge.classList.remove('show');
        scrollBottom(true);
        setTimeout(function(){ inputEl.focus(); },150);
      }
    });
    document.getElementById('irs-chat-close').addEventListener('click', function() {
      isOpen=false; panel.classList.remove('open');
    });

    //  Socket.io 
    var socket = window.io('/', {
      path: '/socket.io',
      auth: { token: token },
      transports: ['websocket','polling'],
    });

    socket.on('connect', function() { subEl.textContent = 'Signed in as ' + myName; });
    socket.on('connect_error', function() { subEl.textContent = 'Connection error - retrying...'; });
    socket.on('disconnect', function() {
      subEl.textContent = 'Disconnected';
      onlineEl.innerHTML = '<span class="irs-dot" style="background:#ef4444"></span>Offline';
    });

    socket.on('chat:history', function(msgs) {
      msgsEl.innerHTML = ''; lastDate = null;
      msgs.forEach(renderMsg);
      scrollBottom(true);
    });

    socket.on('chat:message', function(msg) {
      renderMsg(msg);
      scrollBottom();
      if(!isOpen && msg.username !== myName) {
        unread++;
        badge.textContent = unread > 9 ? '9+' : String(unread);
        badge.classList.add('show');
      }
    });

    socket.on('users:online', function(users) {
      var names = users.map(function(u){ return u.username; });
      onlineEl.innerHTML = '<span class="irs-dot"></span><b>' + names.length + ' online:</b> ' + names.map(esc).join(', ');
      subEl.textContent = names.length + ' member' + (names.length!==1?'s':'') + ' online';
    });

    var typingUsers = {};
    socket.on('chat:typing', function(d) {
      if(d.isTyping) typingUsers[d.username]=true; else delete typingUsers[d.username];
      var names = Object.keys(typingUsers).filter(function(n){ return n!==myName; });
      typingEl.textContent = names.length===0 ? '' :
        names.length===1 ? names[0]+' is typing...' : names.join(', ')+' are typing...';
    });

    //  Send 
    function send() {
      var msg = inputEl.value.trim();
      if(!msg) return;
      socket.emit('chat:send', { message: msg });
      inputEl.value = '';
      socket.emit('chat:typing', false);
      clearTimeout(typingTimer);
    }
    document.getElementById('irs-chat-send').addEventListener('click', send);
    inputEl.addEventListener('keydown', function(e) {
      if(e.key==='Enter' && !e.shiftKey) { e.preventDefault(); send(); }
    });
    inputEl.addEventListener('input', function() {
      socket.emit('chat:typing', true);
      clearTimeout(typingTimer);
      typingTimer = setTimeout(function(){ socket.emit('chat:typing',false); }, 2000);
    });

  } // end run()

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', tryInit);
  } else {
    tryInit();
  }

})();
