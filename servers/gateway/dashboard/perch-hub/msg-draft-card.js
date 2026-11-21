import { tJs } from "../shared/i18n.js";

/**
 * The message draft card in a Perch chat (sharing-bot door plan, PR B).
 *
 * Spliced INSIDE perchHubJs()'s IIFE (client.js), the staged-card.js / mail-draft-card.js pattern, so
 * it shares that scope's el / line / clearEl / live / current / perchApi. It is a SEPARATE file from
 * the mail card on purpose: the mail card sits inside Crow Mail's no-tap invariant test, and adding a
 * second kind of draft to it would put a different door's rules behind that assertion. Its helpers
 * are the mail card's, copied under an `mmsg` prefix, so the two cards read the same but neither can
 * break the other.
 *
 * What it draws, and from where:
 *  - `GET /interactive/:sid/msg-drafts` lists the OPEN drafts this chat made (ids only). Each card is
 *    then read from the owner's own draft route (`/dashboard/messages/api/drafts/:id`), which is where
 *    every field, the seal's verdict (`seal_ok`) and a BOT draft's allow-list (`allowed`) come from.
 *  - A `{type:"msg_draft", id}` frame on this chat's own event stream names one draft that moved; the
 *    card re-reads it and redraws only when something it shows changed.
 *  - `?msgdraft=<id>` in the page's URL mounts that card at the top of the panel, scrolled to and
 *    outlined, for a bell that links straight to it. The id is checked against the store's own shape
 *    before a single request is made.
 *
 * Rules this file keeps:
 *  - Emitted inside a template literal: no backtick and no dollar-brace in the client code; only the
 *    tJs interpolations below.
 *  - The card is built from the fetched draft ONLY, and every name, body character and bot name
 *    reaches the page through `textContent` on a createElement node. A recipient called `<b>Sam</b>`
 *    is text, and a body that looks like markup is text. Nothing here assigns to innerHTML.
 *  - The fixed greyed "Sent by <bot> (bot)" line is read from i18n and is NOT editable: the server
 *    writes that exact line onto the wire (drafts-send.js), so the card only promises what will
 *    happen. The card never puts it in the textarea. The NAME on it is the server's own flattened
 *    attribution (`sent_by_name`, the same `sentByBotName` the wire uses), never the raw bot name:
 *    a bot called `Hank (bot)` would otherwise show `Sent by Hank (bot) (bot)` on the card and send
 *    `Sent by Hank (bot)` — the card must promise exactly what the recipient will read.
 *  - Every write carries the version the card was drawn from. A lost compare-and-set (409 `changed`)
 *    does not overwrite anything: the card says "This draft changed somewhere else." and offers
 *    Reload. A redraw from a frame or a list refresh never replaces local words the server has not
 *    saved — it shows the same sentence instead.
 *  - A draft whose seal does not verify shows the "could not be verified" sentence and NO Send: the
 *    server would refuse it anyway, and offering the button would be a lie.
 *  - Nothing here can send by itself: Send and Discard are two presses a finger makes, and Discard
 *    asks first with the approved confirmation sentence.
 */
export function perchMsgDraftCardJs(lang = "en") {
  return `
  /* ---- the message draft card (bot-door plan, PR B) ---------------------- */
  var MMSG_LANG='${String(lang).replace(/[^a-z-]/g, "")}';
  var MMSG_HEAD='${tJs("messages.draft.cardHead", lang)}';
  var MMSG_TO='${tJs("messages.draft.to", lang)}';
  var MMSG_SENTBY='${tJs("messages.draft.sentByLine", lang)}';
  var MMSG_SEND='${tJs("messages.draft.send", lang)}';
  var MMSG_DISCARD='${tJs("messages.draft.discard", lang)}';
  var MMSG_DISCCONF='${tJs("messages.draft.discardConfirm", lang)}';
  var MMSG_SAVED='${tJs("messages.draft.saved", lang)}';
  var MMSG_SAVING='${tJs("messages.draft.saving", lang)}';
  var MMSG_CHANGED='${tJs("messages.draft.changedElsewhere", lang)}';
  var MMSG_RELOAD='${tJs("messages.draft.reload", lang)}';
  var MMSG_SENT='${tJs("messages.draft.sentReceipt", lang)}';
  var MMSG_DISCARDED='${tJs("messages.draft.discardedReceipt", lang)}';
  var MMSG_UNVERIFIED='${tJs("messages.draft.unverified", lang)}';
  var MMSG_ERR_PUBKEY='${tJs("messages.draft.errPubkey", lang)}';
  var MMSG_ERR_BLOCKED='${tJs("messages.draft.errBlocked", lang)}';
  var MMSG_ERR_NOTALLOWED='${tJs("messages.draft.errNotAllowed", lang)}';
  var MMSG_ERR_GROUP='${tJs("messages.draft.errGroupChanged", lang)}';
  var MMSG_ERR_WAITING='${tJs("messages.draft.errDraftWaiting", lang)}';
  var MMSG_ERR_SEND='${tJs("messages.draft.errSendFailed", lang)}';
  /* A draft id, and nothing else, may reach a URL. */
  var MMSG_ID=/^msgd-[0-9a-f]{32}$/;
  var MMSG_QUERY=/(?:^|[?&])msgdraft=([^&]*)/;
  /* The owner's draft route, the same one the Messages panel writes through. */
  var MMSG_API='/dashboard/messages/api/drafts';
  /* The autosave's own pause: 800 ms after the last keystroke, the words are saved. */
  var MMSG_AUTOSAVE_MS=800;
  /* The two refusals that mean "the row moved under you": re-read it, never overwrite it. */
  var MMSG_STALE={'changed':true,'not_open':true};

  /* One record per card drawn: the node, the answer key it was drawn from, the textarea, the words
     the server holds, and the version every write compares against. */
  var mmsgRec={};
  /* The page's own query card (?msgdraft=) and the chat it was mounted for. */
  var mmsgQueryId=null;
  var mmsgQueryMounted=false;

  function mmsgFill(s,vals){
    var out=String(s);
    var keys=Object.keys(vals||{});
    for(var i=0;i<keys.length;i++) out=out.split('{'+keys[i]+'}').join(String(vals[keys[i]]));
    return out;
  }
  function mmsgText(v){ return v==null?'':String(v); }
  function mmsgList(v){ return Array.isArray(v)?v:[]; }
  function mmsgBtn(parent,cls,text,fn){
    var b=document.createElement('button');
    b.type='button'; b.className=cls; b.textContent=text; b.onclick=fn;
    parent.appendChild(b);
    return b;
  }
  function mmsgBusy(node,on){
    var kids=(node&&node.children)||[];
    for(var i=0;i<kids.length;i++){ if(kids[i]&&kids[i].tagName==='BUTTON') kids[i].disabled=on; }
  }
  function mmsgRemove(node){ if(node&&node.parentNode) node.parentNode.removeChild(node); }
  function mmsgFind(node,cls){
    if(!node) return null;
    if(String(node.className||'').split(' ').indexOf(cls)>=0) return node;
    var kids=node.children||[];
    for(var i=0;i<kids.length;i++){ var hit=mmsgFind(kids[i],cls); if(hit) return hit; }
    return null;
  }
  /* One call on the owner's draft route. A rejected socket answers status 0, never a throw. */
  function mmsgApi(method,path,body){
    var opts={method:method,headers:{'X-Crow-Csrf':csrf()}};
    if(body!==undefined){ opts.headers['Content-Type']='application/json'; opts.body=JSON.stringify(body); }
    return fetch(MMSG_API+path,opts).then(function(r){
      return r.json().catch(function(){return null;}).then(function(j){ return {ok:r.ok,status:r.status,j:j}; });
    },function(){ return {ok:false,status:0,j:null}; });
  }
  /* A refusal's sentence, in the active language, from the route's own code. Nothing the server sends
     back as data reaches the page: every branch is a fixed string from the copy table, filled with
     the recipient's name or the bot's — both of which came from the same read the card was drawn
     from. */
  function mmsgErr(r,rec){
    if(!r||r.status===0) return MMSG_ERR_SEND;
    var j=(r&&r.j)||null;
    var code=(j&&typeof j.error==='string')?j.error:'';
    var name=(rec&&rec.name)||'';
    var bot=(rec&&rec.bot)||'';
    if(code==='pubkey_changed') return mmsgFill(MMSG_ERR_PUBKEY,{name:name});
    if(code==='blocked') return mmsgFill(MMSG_ERR_BLOCKED,{name:name});
    if(code==='not_allowed') return mmsgFill(MMSG_ERR_NOTALLOWED,{bot:bot,name:name});
    if(code==='group_changed'||code==='recipients_changed') return MMSG_ERR_GROUP;
    if(code==='seal_invalid'||code==='seal_unavailable') return MMSG_UNVERIFIED;
    if(code==='changed'||code==='not_open') return MMSG_CHANGED;
    /* The recipient could not be changed because that conversation already has a draft waiting: the
       approved sentence says exactly that, and it is the one thing that helps (send or discard the
       draft already there). Nothing about THIS row moved, so it is not the "changed somewhere else"
       line, and Reload would fix nothing. */
    if(code==='owner_draft_open') return MMSG_ERR_WAITING;
    if(code==='conversation_gone') return MMSG_ERR_SEND;
    return MMSG_ERR_SEND;
  }

  /* ---- the recipient chip -------------------------------------------------- */
  /* A BOT's draft is addressed by the operator now, inside the permission the bot was given: a
     picker whose options are exactly the allow-list entries the route resolved (the answer's
     allowed list), each value the conversation the draft route takes. Choosing one re-addresses the
     draft (POST /:id/recipient) — the words are untouched and the server re-runs every rail of the
     bot's send before it moves. The entry the draft is already for is the selected one; a recipient
     the bot may no longer write to is shown (not hidden) as a disabled first option, so the person
     sees who the draft is for rather than a picker quietly claiming somebody else. */
  function mmsgPicker(card,payload,rec,refetch){
    var draft=payload.draft||{};
    var allowed=payload.allowed||null;
    var entries=mmsgList(allowed&&allowed.contacts).map(function(contact){
      return {
        value:'contact:'+Number(contact.conversationId),
        text:mmsgText(contact.name),
      };
    }).concat(mmsgList(allowed&&allowed.groups).map(function(group){
      return {
        value:'room:'+Number(group.conversationId),
        text:mmsgText(group.name),
      };
    }));
    var current=mmsgText(draft.conversationKind)+':'+Number(draft.conversationId);
    if(!entries.length) return false;
    var sel=document.createElement('select');
    sel.className='mmsg-recipient-picker';
    sel.setAttribute('aria-label',MMSG_TO);
    var known=false;
    for(var i=0;i<entries.length;i++){
      if(entries[i].value===current) known=true;
      var opt=document.createElement('option');
      opt.value=entries[i].value;
      opt.textContent=entries[i].text;
      if(entries[i].value===current) opt.setAttribute('selected','selected');
      sel.appendChild(opt);
    }
    if(!known){
      var mine=document.createElement('option');
      mine.value=''; mine.textContent=rec.name||current;
      mine.setAttribute('selected','selected'); mine.disabled=true;
      sel.insertBefore(mine,sel.firstChild);
    }
    sel.onchange=function(){
      var value=mmsgText(sel.value);
      var m=/^(contact|room):([0-9]{1,12})$/.exec(value);
      if(!m||value===current) return;
      sel.disabled=true;
      mmsgApi('POST','/'+encodeURIComponent(rec.id)+'/recipient',{
        conversationKind:m[1],
        conversationId:Number(m[2]),
        expectVersion:Number(rec.version),
      }).then(function(r){
        if(!live()) return;
        sel.disabled=false;
        if(r&&r.ok&&r.j){ refetch(); return; }
        if(r&&r.j&&r.j.draft&&r.j.draft.version) rec.version=Number(r.j.draft.version)||rec.version;
        if(rec.status) rec.status.textContent=mmsgErr(r,rec);
      });
    };
    var wrap=document.createElement('div'); wrap.className='mmsg-to';
    wrap.appendChild(line('mmsg-label',MMSG_TO));
    wrap.appendChild(sel);
    card.appendChild(wrap);
    return true;
  }

  /* ---- one card ------------------------------------------------------------ */
  function mmsgKey(payload){
    var draft=payload.draft||{};
    var allowed=payload.allowed||{};
    return [
      mmsgText(draft.state),mmsgText(draft.version),mmsgText(draft.body),mmsgText(draft.label),
      mmsgText(draft.conversationKind),mmsgText(draft.conversationId),mmsgText(draft.botName),
      payload.seal_ok===false?'0':'1',
      mmsgList(allowed.contacts).length+'/'+mmsgList(allowed.groups).length,
    ].join('|');
  }

  /* A one-line receipt: a draft that has left (sent or discarded) keeps a card that says so, and
     nothing to press. */
  function mmsgReceipt(card,payload,rec){
    var draft=payload.draft||{};
    var text=String(draft.state)==='sent'
      ? mmsgFill(MMSG_SENT,{name:mmsgText(draft.label)})
      : MMSG_DISCARDED;
    card.appendChild(line('mmsg-receipt',text));
    rec.terminal=true;
    rec.box=null;
    return { card:card, rec:rec };
  }

  /* The one Discard press, shared by a draft that can be sent and one whose seal does not verify
     (the sentence that explains that one tells the person to discard it). */
  function mmsgDiscardBtn(actions,rec,status,refetch){
    mmsgBtn(actions,'mmsg-discard',MMSG_DISCARD,function(){
      var yes=false;
      try{ yes=confirm(MMSG_DISCCONF)?true:false; }catch(e){ yes=false; }
      if(!yes) return;
      mmsgBusy(actions,true);
      rec.busy=true;
      mmsgApi('POST','/'+encodeURIComponent(rec.id)+'/discard',{expectVersion:Number(rec.version)})
        .then(function(r){
          if(!live()) return;
          rec.busy=false;
          if(r&&r.ok){ refetch(); return; }
          mmsgBusy(actions,false);
          if(r&&MMSG_STALE[String((r.j&&r.j.error)||'')]){ rec.stale=true; mmsgShowChanged(rec,refetch); return; }
          status.textContent=mmsgErr(r,rec);
        });
    });
  }

  function mmsgCard(payload,refetch,notice){
    var draft=payload.draft||{};
    var state=mmsgText(draft.state||'open');
    var bot=mmsgText(draft.botName)||mmsgText(draft.botId);
    /* The name the greyed line promises: the SERVER's flattened attribution when the answer carries
       one (the string the wire uses), else the bot name the card was drawn with. */
    var sentBy=mmsgText(draft.sent_by_name)||bot;
    var label=mmsgText(draft.label);
    var rec={
      id:mmsgText(draft.id),
      name:label,
      bot:bot,
      conversation:mmsgText(draft.conversationKind)+':'+Number(draft.conversationId),
      version:Number(draft.version)||0,
      saved:mmsgText(draft.body),
      state:state,
      box:null,
      status:null,
      actions:null,
      stale:false,
      terminal:false,
      busy:false,
      timer:null,
      sid:null,
      top:false,
      node:null,
      key:'',
    };
    var card=document.createElement('div');
    card.className='entry mmsg-card';
    card.setAttribute('data-msgdraft-id',rec.id);
    card.setAttribute('role','group');
    var heading=mmsgFill(MMSG_HEAD,{bot:bot||label});
    card.setAttribute('aria-label',heading);
    card.appendChild(line('mmsg-head',heading));

    if(state==='sent'||state==='discarded') return mmsgReceipt(card,payload,rec);

    /* Who it is for: a picker for a bot's draft (the allow-list), a plain chip otherwise. */
    if(!(bot&&mmsgPicker(card,payload,rec,refetch))){
      var row=document.createElement('div'); row.className='mmsg-to';
      row.appendChild(line('mmsg-label',MMSG_TO));
      row.appendChild(line('mmsg-chip',label));
      card.appendChild(row);
    }
    /* The fixed line the message will begin with: greyed, and never editable. */
    if(bot) card.appendChild(line('mmsg-sentby',mmsgFill(MMSG_SENTBY,{bot:sentBy})));

    var verified=payload.seal_ok!==false;
    if(!verified) card.appendChild(line('mmsg-unverified',MMSG_UNVERIFIED));

    var status=line('mmsg-status','');
    status.setAttribute('role','status');
    var actions=document.createElement('div'); actions.className='mmsg-actions';
    rec.status=status;
    rec.actions=actions;

    if(verified){
      var box=document.createElement('textarea');
      box.className='mmsg-body';
      box.value=rec.saved;
      box.setAttribute('aria-label',MMSG_TO);
      card.appendChild(box);
      rec.box=box;
      /* The autosave: 800 ms after the last keystroke, the words go through the same compare-and-set
         the Messages composer uses. Nothing is written for an empty or unchanged box. */
      box.oninput=function(){
        if(rec.timer!=null){ clearTimeout(rec.timer); rec.timer=null; }
        if(rec.stale) return;
        rec.timer=setTimeout(function(){ rec.timer=null; mmsgAutosave(rec,refetch); },MMSG_AUTOSAVE_MS);
      };
    }

    card.appendChild(status);
    card.appendChild(actions);

    /* A draft that cannot be verified offers no Send at all: the server would refuse it. */
    if(state==='open'&&verified&&rec.box){
      mmsgBtn(actions,'primary mmsg-send',MMSG_SEND,function(){
        var text=String(rec.box.value==null?'':rec.box.value);
        if(!text.trim()) return;
        mmsgBusy(actions,true);
        rec.busy=true;
        mmsgApi('POST','/'+encodeURIComponent(rec.id)+'/send',{body:text,expectVersion:Number(rec.version)})
          .then(function(r){
            if(!live()) return;
            rec.busy=false;
            if(r&&r.ok){
              /* The words just left: they are no longer unsaved local words, so the receipt may
                 replace the card (mmsgDraw's dirty guard must not read this as a clobber). */
              rec.saved=text;
              if(r.j&&r.j.draft&&r.j.draft.version) rec.version=Number(r.j.draft.version)||rec.version;
              refetch();
              return;
            }
            mmsgBusy(actions,false);
            if(r&&r.j&&r.j.draft&&r.j.draft.version) rec.version=Number(r.j.draft.version)||rec.version;
            if(r&&MMSG_STALE[String((r.j&&r.j.error)||'')]){
              rec.stale=true;
              mmsgShowChanged(rec,refetch);
              return;
            }
            status.textContent=mmsgErr(r,rec);
          });
      });
    }
    mmsgDiscardBtn(actions,rec,status,refetch);

    if(mmsgText(notice)) status.textContent=mmsgText(notice);
    return { card:card, rec:rec };
  }

  /* "This draft changed somewhere else." plus the one thing that can be done about it: read it again.
     The person's own unsaved words are never thrown away by a redraw. */
  function mmsgShowChanged(rec,refetch){
    if(!rec||!rec.status) return;
    rec.status.textContent=MMSG_CHANGED;
    if(!rec.actions||mmsgFind(rec.actions,'mmsg-reload')) return;
    mmsgBtn(rec.actions,'mmsg-reload',MMSG_RELOAD,function(){
      rec.stale=false;
      refetch(rec.id,true);
    });
  }

  function mmsgAutosave(rec,refetch){
    if(!rec||!rec.box||rec.stale) return;
    var text=String(rec.box.value==null?'':rec.box.value);
    if(text===rec.saved) return;
    if(rec.status) rec.status.textContent=MMSG_SAVING;
    rec.busy=true;
    mmsgApi('PATCH','/'+encodeURIComponent(rec.id)+'/body',{body:text,expectVersion:Number(rec.version)})
      .then(function(r){
        if(!live()) return;
        rec.busy=false;
        if(r&&r.ok&&r.j&&r.j.draft){
          rec.version=Number(r.j.draft.version)||rec.version;
          rec.saved=text;
          if(rec.status) rec.status.textContent=MMSG_SAVED;
          return;
        }
        if(r&&MMSG_STALE[String((r.j&&r.j.error)||'')]){ rec.stale=true; mmsgShowChanged(rec,refetch); return; }
        if(rec.status) rec.status.textContent=mmsgErr(r,rec);
      });
  }

  /* Draw one answer, replacing the card that was drawn from a different one. A card whose textarea
     holds words the server has not saved is NOT replaced: the sentence and Reload land on it
     instead. opts.top mounts at the top of the panel (the query card), opts.sid is the chat the read
     was made for, opts.force replaces even over local words (the person pressed Reload). */
  function mmsgDraw(payload,opts,notice){
    var draft=payload&&payload.draft?payload.draft:null;
    if(!draft) return null;
    var id=mmsgText(draft.id);
    if(!MMSG_ID.test(id)) return null;
    var key=mmsgKey(payload);
    var old=mmsgRec[id]||null;
    var note=mmsgText(notice);
    if(old&&old.node&&old.node.parentNode){
      /* The words the server holds are the words this card already holds — an autosave's own echo, or
         another writer who typed the same thing. Take the version the read carries and leave the DOM
         alone, so the caret and the status line survive a redraw nobody asked for. */
      var incoming=mmsgText(draft.body);
      var incomingConversation=mmsgText(draft.conversationKind)+':'+Number(draft.conversationId);
      if(old.box&&mmsgText(draft.state||'open')==='open'&&incoming===old.saved
        &&incomingConversation===old.conversation){
        old.version=Number(draft.version)||old.version;
        old.key=key;
        if(note&&old.status) old.status.textContent=note;
        return old.node;
      }
      /* A write of this card's own is in flight: its answer is the truth about this row, and redrawing
         under the person's fingers would be the clobber the guard below exists to stop. */
      if(!(opts&&opts.force)&&old.busy) return old.node;
      var dirty=false;
      if(old.box) dirty=String(old.box.value==null?'':old.box.value)!==old.saved;
      if(!(opts&&opts.force)&&dirty&&old.key!==key){
        mmsgShowChanged(old,function(nextId,force){ mmsgLoad(nextId||id,opts,null,force); });
        return old.node;
      }
      if(old.key===key){
        if(note&&old.status) old.status.textContent=note;
        return old.node;
      }
    }
    var built=mmsgCard(payload,function(nextId,force){
      mmsgLoad(nextId||id,opts,null,force);
    },note);
    if(!built) return null;
    var node=built.card;
    var rec=built.rec;
    rec.key=key;
    rec.sid=(opts&&opts.sid)?String(opts.sid):null;
    rec.top=!!(opts&&opts.top);
    if(old&&old.node&&old.node.parentNode){
      old.node.parentNode.insertBefore(node,old.node);
      old.node.parentNode.removeChild(old.node);
    }else{
      var tr=el('perch-transcript');
      if(!tr) return null;
      if(opts&&opts.top) tr.insertBefore(node,tr.firstChild);
      else tr.appendChild(node);
    }
    rec.node=node;
    mmsgRec[id]=rec;
    if(opts&&opts.scroll){
      try{ if(typeof node.scrollIntoView==='function') node.scrollIntoView({block:'center'}); }catch(e){}
    }
    return node;
  }

  /* Read one draft and draw it. A read that lands after a session switch draws nothing. */
  function mmsgLoad(id,opts,notice,force){
    var myId=mmsgText(id);
    if(!MMSG_ID.test(myId)) return null;
    var o=opts||{};
    if(force) o=Object.assign({},o,{force:true});
    return mmsgApi('GET','/'+encodeURIComponent(myId)).then(function(r){
      if(!live()) return null;
      if(o.sid&&current.sid!==String(o.sid)) return null;
      if(!r||!r.ok||!r.j||!r.j.draft) return null;
      return mmsgDraw(r.j,o,notice);
    });
  }

  /* The ids this chat's own drafts list returns. The list is ids only: each card is read from the
     draft route, which is where the fields, the seal's verdict and the allow-list come from. */
  function loadMsgDrafts(sid){
    if(!sid) return;
    var mySid=String(sid);
    perchApi('GET','/interactive/'+encodeURIComponent(mySid)+'/msg-drafts').then(function(r){
      if(!live()||current.sid!==mySid) return;
      if(!r||!r.ok||!r.j||!Array.isArray(r.j.drafts)) return;
      var ids=[];
      for(var i=0;i<r.j.drafts.length;i++){
        var entry=r.j.drafts[i];
        if(entry&&typeof entry.id==='string'&&MMSG_ID.test(entry.id)) ids.push(entry.id);
      }
      mmsgPrune(ids);
      /* Oldest first, so the newest draft lands last, where the eye already is. */
      for(var k=ids.length-1;k>=0;k--) mmsgLoad(ids[k],{sid:mySid});
    });
  }

  /* Cards the list no longer names are gone — except the page's own query card, and a receipt: a
     draft that has left keeps its one line, which is how "sent" and "discarded" stay explained. */
  function mmsgPrune(ids){
    var keep={};
    for(var i=0;i<ids.length;i++) keep[ids[i]]=true;
    if(mmsgQueryId) keep[mmsgQueryId]=true;
    var known=Object.keys(mmsgRec);
    for(var k=0;k<known.length;k++){
      var id=known[k];
      var rec=mmsgRec[id];
      if(keep[id]||(rec&&rec.terminal)) continue;
      if(rec) mmsgForget(rec);
    }
  }
  function mmsgForget(rec){
    if(!rec) return;
    if(rec.timer!=null){ clearTimeout(rec.timer); rec.timer=null; }
    mmsgRemove(rec.node);
    delete mmsgRec[rec.id];
  }

  /* The draft id in the page's own query, checked against the store's shape BEFORE any request. */
  function mmsgQuery(){
    var q='';
    try{ q=mmsgText(location.search); }catch(e){ q=''; }
    var m=MMSG_QUERY.exec(q);
    if(!m) return null;
    return MMSG_ID.test(m[1])?m[1]:null;
  }

  /* A bell that links straight to a draft mounts it at the top of the panel, once per page load,
     scrolled to and outlined by the card's own class. */
  function loadMsgDraftFromQuery(){
    if(mmsgQueryMounted) return;
    var id=mmsgQuery();
    if(!id) return;
    mmsgQueryId=id;
    var node=mmsgLoad(id,{top:true,scroll:true});
    if(node&&typeof node.then==='function'){
      node.then(function(drawn){
        if(!drawn) return;
        mmsgQueryMounted=true;
        if(String(drawn.className||'').indexOf('mmsg-query')<0) drawn.className+=' mmsg-query';
      });
    }
  }

  /* A {type:"msg_draft", id} frame on this chat's own stream: one draft moved. Re-read it; a card
     that holds unsaved words is told so instead of being replaced (mmsgDraw). A draft this chat did
     not make never reaches here (the server matches on the chat's own id). */
  function mmsgFrame(d){
    var id=mmsgText(d&&d.id);
    if(!MMSG_ID.test(id)) return;
    mmsgLoad(id,{sid:current.sid});
  }

  /* A session switch: the transcript, and every card in it, is gone — except the page's own query
     card, which belongs to no chat. It goes back to the top. */
  function resetMsgDrafts(){
    var keep=mmsgQueryId;
    var known=Object.keys(mmsgRec);
    for(var i=0;i<known.length;i++){
      if(keep&&known[i]===keep) continue;
      mmsgForget(mmsgRec[known[i]]);
    }
    var rec=keep?mmsgRec[keep]:null;
    var tr=el('perch-transcript');
    if(rec&&rec.node&&tr&&rec.node.parentNode!==tr) tr.insertBefore(rec.node,tr.firstChild);
  }
`;
}