import { tJs } from "../shared/i18n.js";

/**
 * The report card in a Perch chat.
 *
 * Spliced INSIDE perchHubJs()'s IIFE (client.js), the mail-draft-card.js pattern, so it shares that
 * scope's el / line / clearEl / live / current / csrf / perchApi. One card per report: the chat's own
 * report ids come from GET /interactive/:sid/reports (ids only), and every card is built from GET
 * /dashboard/api/reports/:id/card.
 *
 * Rules:
 *  - Emitted inside a template literal: no backtick and no dollar-brace in the client code; only the
 *    tJs interpolations below.
 *  - The card is built from the fetched card ONLY, and every title, address, display name, host,
 *    block id, settings value and diff line reaches the page through textContent on a createElement
 *    node: a title that looks like markup is text.
 *  - Every button is a POST a finger makes, under /dashboard/api/reports/<id>/..., carrying the hub's
 *    CSRF header. Nothing here previews, applies, approves or goes live by itself, and there is no
 *    control for running a report now or sending anything.
 *  - A refusal shows the server's own fixed sentence in the card's status line; a lost connection
 *    (status 0) shows the offline sentence. A raw error code never reaches the page. A 409
 *    `conflict` (the row moved under the owner) reads the card again and carries the server's
 *    sentence onto the card that replaces the tapped one.
 *  - Every tap echoes the revision the owner is looking at, taken from the SAME card JSON that put
 *    the values on screen: Apply posts the card's headRev and changesHash, go-live the sender's
 *    accountId, a source approve its settingsHash. Nothing is re-read between display and tap.
 *  - After any tap the card is read again, and an unchanged answer redraws nothing (the card is
 *    keyed on its own JSON). A card whose preview is queued or running polls its own read every 3 s
 *    for its first five polls, then 15 s, then a minute; a hidden tab asks for nothing, and a session
 *    switch stops the polls the transcript took with it. The chat's report ids are re-read every 8 s
 *    while the chat is live and the tab visible, so a report the bot makes mid-chat appears, and one
 *    that disappears from the list is removed.
 *  - The owner sees everything a tap would put under their approval: a change's before and after
 *    settings and a source's settings are printed in FULL as key: value lines, never truncated. The
 *    one capped block is a pending step's diff, whose file count line stays true beside it.
 *  - A card whose change list the server had to shorten (`changesTruncated`) lists the entries it
 *    has, says so, and offers no Apply: a shortened list is not something to approve unseen.
 */
export function perchReportCardJs(lang = "en") {
  return `
  /* ---- the report card -------------------------------------------------- */
  var RCARD_STATUS_DRAFT='${tJs("reports.card.statusDraft", lang)}';
  var RCARD_STATUS_LIVE='${tJs("reports.card.statusLive", lang)}';
  var RCARD_STATUS_PAUSED='${tJs("reports.card.statusPaused", lang)}';
  var RCARD_SEND_FROM='${tJs("reports.card.sendFrom", lang)}';
  var RCARD_KIND_GOOGLE='${tJs("reports.card.kindGoogle", lang)}';
  var RCARD_KIND_CROW='${tJs("reports.card.kindCrow", lang)}';
  var RCARD_PREVIEW='${tJs("reports.card.preview", lang)}';
  var RCARD_GO_LIVE='${tJs("reports.card.goLive", lang)}';
  var RCARD_APPLY='${tJs("reports.card.apply", lang)}';
  var RCARD_APPROVE_SOURCE='${tJs("reports.card.approveSource", lang)}';
  var RCARD_APPROVE='${tJs("reports.card.approve", lang)}';
  var RCARD_REFUSE='${tJs("reports.card.refuse", lang)}';
  var RCARD_PREVIEW_FIRST='${tJs("reports.card.previewFirst", lang)}';
  var RCARD_PREVIEW_QUEUED='${tJs("reports.card.previewQueued", lang)}';
  var RCARD_PREVIEW_RUNNING='${tJs("reports.card.previewRunning", lang)}';
  var RCARD_CHANGES='${tJs("reports.card.changes", lang)}';
  var RCARD_SOURCES='${tJs("reports.card.sources", lang)}';
  var RCARD_RECIPIENTS='${tJs("reports.card.recipients", lang)}';
  var RCARD_STEPS='${tJs("reports.card.steps", lang)}';
  var RCARD_HOSTS='${tJs("reports.card.hosts", lang)}';
  var RCARD_CREDENTIALS='${tJs("reports.card.credentials", lang)}';
  var RCARD_ADDED='${tJs("reports.card.added", lang)}';
  var RCARD_CHANGED='${tJs("reports.card.changed", lang)}';
  var RCARD_REMOVED='${tJs("reports.card.removed", lang)}';
  var RCARD_WHOLE_REPORT='${tJs("reports.card.wholeReport", lang)}';
  var RCARD_BLOCK_ORDER='${tJs("reports.card.blockOrder", lang)}';
  var RCARD_BEFORE='${tJs("reports.card.before", lang)}';
  var RCARD_AFTER='${tJs("reports.card.after", lang)}';
  var RCARD_SETTINGS='${tJs("reports.card.settings", lang)}';
  var RCARD_TOO_LARGE='${tJs("reports.card.tooLarge", lang)}';
  var RCARD_CHANGES_TRUNCATED='${tJs("reports.card.changesTruncated", lang)}';
  var RCARD_FILE_COUNTS='${tJs("reports.card.fileCounts", lang)}';
  var RCARD_MORE_LINES='${tJs("reports.card.moreLines", lang)}';
  var RCARD_STEP_META='${tJs("reports.card.stepMeta", lang)}';
  var RCARD_SCHEDULE_PROPOSAL='${tJs("reports.card.scheduleProposal", lang)}';
  var RCARD_OFFLINE='${tJs("reports.card.offline", lang)}';
  var RCARD_FAILED='${tJs("reports.card.failed", lang)}';
  /* The owner routes the taps call, and the report card read. */
  var RCARD_API='/dashboard/api/reports';
  /* A report id, and nothing else, may reach a URL. */
  var RCARD_ID=/^rpt-[0-9a-f]{16}$/;
  /* A diff is printed whole by the server; the card caps one file's lines here, and says so. */
  var RCARD_DIFF_MAX=200;
  var RCARD_STATUS_WORDS={'draft':RCARD_STATUS_DRAFT,'live':RCARD_STATUS_LIVE,
    'paused':RCARD_STATUS_PAUSED};
  var RCARD_KIND_WORDS={'google_reports':RCARD_KIND_GOOGLE,'crow_mail':RCARD_KIND_CROW};
  var RCARD_CHANGE_WORDS={'added':RCARD_ADDED,'changed':RCARD_CHANGED,'removed':RCARD_REMOVED};
  /* The states whose preview is still moving on the server's side. */
  var RCARD_PREVIEW_STATES={'queued':true,'running':true};
  /* The answer that means the row moved under the owner: the card is read again, with the server's
     own sentence carried onto the card that replaces the tapped one. */
  var RCARD_CONFLICT={'conflict':true};
  /* The poll's gap widens as a card stays in one state: 3 s for its first five polls, then 15 s,
     then a minute. A hidden tab asks for nothing. The id list is re-read on its own slower beat. */
  var RCARD_POLL_MS=3000;
  var RCARD_POLL_SLOW_MS=15000;
  var RCARD_POLL_SLOWEST_MS=60000;
  var RCARD_POLL_FAST=5;
  var RCARD_LIST_MS=8000;

  /* The report cards drawn so far: id -> the node, the answer key it was drawn from, the chat it was
     read for, the preview state it was drawn in, and its poll's timer and count. */
  var rcardNodes={};
  var rcardKeys={};
  var rcardSid={};
  var rcardPreview={};
  var rcardPollTimers={};
  var rcardPollCounts={};
  /* The chat's own id-list poll: one timer, for one chat. */
  var rcardListTimer=null;
  var rcardListSid=null;

  function rcardFill(s,vals){
    var out=String(s);
    var keys=Object.keys(vals||{});
    for(var i=0;i<keys.length;i++) out=out.split('{'+keys[i]+'}').join(String(vals[keys[i]]));
    return out;
  }
  function rcardText(v){ return v==null?'':String(v); }
  function rcardList(v){ return Array.isArray(v)?v:[]; }
  function rcardBtn(parent,cls,text,fn){
    var b=document.createElement('button');
    b.type='button'; b.className=cls; b.textContent=text; b.onclick=fn;
    parent.appendChild(b);
    return b;
  }
  function rcardBusy(node,on){
    var kids=(node&&node.children)||[];
    for(var i=0;i<kids.length;i++){
      var k=kids[i];
      if(!k) continue;
      if(k.tagName==='BUTTON') k.disabled=on;
      else rcardBusy(k,on);
    }
  }
  function rcardRemove(node){ if(node&&node.parentNode) node.parentNode.removeChild(node); }
  /* One value as the person reads it: a plain value verbatim, anything nested as its JSON. Nothing
     is shortened: this is the settings a tap puts under the owner's approval. */
  function rcardValue(v){
    if(v==null) return '';
    if(typeof v==='string') return v;
    if(typeof v==='number'||typeof v==='boolean') return String(v);
    try{ return JSON.stringify(v); }catch(e){ return String(v); }
  }
  /* A settings object, a key: value line each, under its own label. A block that is absent on one
     side of a change prints nothing there: the change word already says it. */
  function rcardSettings(parent,label,settings){
    if(!settings||typeof settings!=='object') return;
    if(label) parent.appendChild(line('rcard-label',label));
    var box=document.createElement('div'); box.className='rcard-settings';
    var keys=Object.keys(settings);
    for(var i=0;i<keys.length;i++){
      box.appendChild(line('rcard-setting',keys[i]+': '+rcardValue(settings[keys[i]])));
    }
    parent.appendChild(box);
  }
  /* One call on the owner's report routes. A rejected socket answers the offline line, never a throw. */
  function rcardApi(method,path,body){
    var opts={method:method,headers:{'X-Crow-Csrf':csrf()}};
    if(body!==undefined){ opts.headers['Content-Type']='application/json'; opts.body=JSON.stringify(body); }
    return fetch(RCARD_API+path,opts).then(function(r){
      return r.json().catch(function(){return null;}).then(function(j){ return {ok:r.ok,status:r.status,j:j}; });
    },function(){ return {ok:false,status:0,j:null}; });
  }
  /* A refusal's line: the server's own fixed sentence, never its raw code. The offline sentence is
     for a lost connection; a failure with no sentence of its own falls back to the card's own. */
  function rcardRefusal(r){
    if(!r||r.status===0) return RCARD_OFFLINE;
    var j=(r&&r.j)||null;
    if(j&&typeof j.message==='string'&&j.message) return j.message;
    return RCARD_FAILED;
  }
  /* The sentence a conflict hands to the card that replaces the tapped one: the server's own message
     where it sent one, else the card's fixed failure line. */
  function rcardNotice(r){
    var j=(r&&r.j)||null;
    if(j&&typeof j.message==='string'&&j.message) return j.message;
    return rcardRefusal(r);
  }
  /* After a conflict, read the card again and carry the sentence through: this node is about to be
     gone, so the sentence has to land on the card the owner is looking at next. Answers the text to
     show in place when nothing is refetched. */
  function rcardSettleRefusal(r,after){
    var j=(r&&r.j)||null;
    var code=(j&&typeof j.error==='string')?j.error:'';
    if(typeof after==='function'&&r&&r.status===409&&RCARD_CONFLICT[code]){
      after(rcardNotice(r));
      return '';
    }
    return rcardRefusal(r);
  }
  function rcardFind(node,cls){
    if(!node) return null;
    if(String(node.className||'').split(' ').indexOf(cls)>=0) return node;
    var kids=node.children||[];
    for(var i=0;i<kids.length;i++){ var hit=rcardFind(kids[i],cls); if(hit) return hit; }
    return null;
  }
  /* The status node of a card already on screen, so a notice can land on it without a redraw. */
  function rcardNoticeWrite(node,text){
    var note=rcardText(text);
    if(!node||!note) return;
    var status=rcardFind(node,'rcard-status');
    if(status) status.textContent=note;
  }
  function rcardKind(kind){
    var k=rcardText(kind);
    var known=RCARD_KIND_WORDS[k];
    return typeof known==='string'?known:k;
  }
  function rcardStatusWord(status){
    var s=rcardText(status);
    var known=RCARD_STATUS_WORDS[s];
    return typeof known==='string'?known:s;
  }
  function rcardChangeWord(change){
    var c=rcardText(change);
    var known=RCARD_CHANGE_WORDS[c];
    return typeof known==='string'?known:c;
  }
  /* A current preview is what go-live needs; a report already live at that revision has nothing left
     to publish, so it offers no button. */
  function rcardCanGoLive(report,preview){
    if(!preview||!preview.current) return false;
    if(report&&report.live&&Number(report.liveRev)===Number(preview.recipeRev)) return false;
    return true;
  }
  /* Apply is one tap only for a free change: a source or custom change is its own approval, and a
     change list the server cannot show is not something to approve unseen. */
  function rcardCanApply(card){
    var report=(card&&card.report)||{};
    if(!report.pendingFreeChange) return false;
    if(card&&card.changesUnreadable) return false;
    if(card&&card.changesTruncated) return false;
    var changes=rcardList(card&&card.changes);
    if(!changes.length) return false;
    for(var i=0;i<changes.length;i++){
      var kind=rcardText(changes[i]&&changes[i].kind);
      if(kind==='source'||kind==='custom') return false;
    }
    return true;
  }

  /* ---- the sections ----------------------------------------------------- */
  /* Every change: its block, its type, the change word, and the full settings on both sides. A
     recipe-level change and a reordering name no block, so each says what its entry is about in the
     block line instead of showing an empty one and a raw type word. */
  function rcardChangeLabel(type){
    var tp=rcardText(type);
    if(tp==='recipe') return RCARD_WHOLE_REPORT;
    if(tp==='order') return RCARD_BLOCK_ORDER;
    return null;
  }
  function rcardChanges(node,card){
    var changes=rcardList(card.changes);
    var truncated=!!(card&&card.changesTruncated);
    if(!changes.length&&!truncated) return;
    node.appendChild(line('rcard-h',RCARD_CHANGES));
    if(truncated){
      node.appendChild(line('rcard-changes-truncated rcard-truncated',RCARD_CHANGES_TRUNCATED));
    }
    for(var i=0;i<changes.length;i++){
      var ch=changes[i]||{};
      var label=rcardChangeLabel(ch.type);
      var row=document.createElement('div'); row.className='rcard-change';
      if(label!==null){
        row.appendChild(line('rcard-block',label));
      }else{
        row.appendChild(line('rcard-block',ch.blockId));
        row.appendChild(line('rcard-type',ch.type));
      }
      row.appendChild(line('rcard-change-word',rcardChangeWord(ch.change)));
      rcardSettings(row,RCARD_BEFORE,ch.before);
      rcardSettings(row,RCARD_AFTER,ch.after);
      node.appendChild(row);
    }
  }
  /* A draft source: its block, its type and its full settings above its own approval. A source too
     large for the server to hand over says so and offers no button. */
  function rcardSources(node,card,refetch,status){
    var sources=rcardList(card.sources);
    if(!sources.length) return;
    node.appendChild(line('rcard-h',RCARD_SOURCES));
    for(var i=0;i<sources.length;i++){
      (function(src){
        var row=document.createElement('div'); row.className='rcard-source';
        row.appendChild(line('rcard-block',src.blockId));
        row.appendChild(line('rcard-type',src.type));
        if(src.truncated){
          row.appendChild(line('rcard-truncated',RCARD_TOO_LARGE));
        }else{
          rcardSettings(row,RCARD_SETTINGS,src.settings);
          rcardBtn(row,'rcard-source-approve',RCARD_APPROVE_SOURCE,function(){
            rcardPost(node,status,refetch,'sources/'+encodeURIComponent(rcardText(src.blockId))+
              '/approve',{settingsHash:rcardText(src.settingsHash)});
          });
        }
        node.appendChild(row);
      })(sources[i]||{});
    }
  }
  /* Proposed recipients carry Approve and Refuse; approved ones are listed without buttons. */
  function rcardRecipients(node,card,refetch,status){
    var rcpts=rcardList(card.recipients);
    if(!rcpts.length) return;
    node.appendChild(line('rcard-h',RCARD_RECIPIENTS));
    for(var i=0;i<rcpts.length;i++){
      (function(rp){
        var row=document.createElement('div'); row.className='rcard-rcpt';
        row.appendChild(line('rcard-addr',rp.address));
        if(rp.displayName) row.appendChild(line('rcard-name',rp.displayName));
        if(rp.commentTier) row.appendChild(line('rcard-tier',rp.commentTier));
        if(rcardText(rp.state)==='proposed'){
          var base='recipients/'+encodeURIComponent(rcardText(rp.id));
          rcardBtn(row,'rcard-rcpt-approve',RCARD_APPROVE,function(){
            rcardPost(node,status,refetch,base+'/approve',undefined);
          });
          rcardBtn(row,'rcard-rcpt-refuse',RCARD_REFUSE,function(){
            rcardPost(node,status,refetch,base+'/refuse',undefined);
          });
        }
        node.appendChild(row);
      })(rcpts[i]||{});
    }
  }
  /* One file of a pending step: its path, its counts, and its diff. The server hands the whole diff;
     the cap here is one file's printed lines, and the line after it says so. */
  function rcardStepFiles(row,step){
    var files=rcardList(step.files);
    for(var i=0;i<files.length;i++){
      var f=files[i]||{};
      row.appendChild(line('rcard-step-path',f.path));
      row.appendChild(line('rcard-step-counts',rcardFill(RCARD_FILE_COUNTS,
        {added:Number(f.added)||0,removed:Number(f.removed)||0})));
      var lines=rcardList(f.lines);
      var box=document.createElement('div'); box.className='rcard-diff';
      var shown=lines.length>RCARD_DIFF_MAX?RCARD_DIFF_MAX:lines.length;
      for(var k=0;k<shown;k++){
        var seg=lines[k]||{};
        box.appendChild(line('rcard-diff-line',rcardText(seg.op)+rcardText(seg.text)));
      }
      row.appendChild(box);
      if(lines.length>shown) row.appendChild(line('rcard-more',RCARD_MORE_LINES));
    }
  }
  /* A proposed step's revision: its key, revision, language and entry, its files, then its own
     approval. Nothing here runs it. */
  function rcardSteps(node,card,refetch,status){
    var steps=rcardList(card.steps);
    if(!steps.length) return;
    node.appendChild(line('rcard-h',RCARD_STEPS));
    for(var i=0;i<steps.length;i++){
      (function(step){
        var row=document.createElement('div'); row.className='rcard-step';
        row.appendChild(line('rcard-step-key',step.stepKey));
        row.appendChild(line('rcard-step-meta',rcardFill(RCARD_STEP_META,
          {rev:rcardText(step.rev),language:rcardText(step.language)})));
        row.appendChild(line('rcard-step-entry',step.entry));
        rcardStepFiles(row,step);
        var base='steps/'+encodeURIComponent(rcardText(step.stepKey))+'/'+
          encodeURIComponent(rcardText(step.rev));
        rcardBtn(row,'rcard-step-approve',RCARD_APPROVE,function(){
          rcardPost(node,status,refetch,base+'/approve',{bundleHash:rcardText(step.bundleHash)});
        });
        rcardBtn(row,'rcard-step-refuse',RCARD_REFUSE,function(){
          rcardPost(node,status,refetch,base+'/refuse',undefined);
        });
        node.appendChild(row);
      })(steps[i]||{});
    }
  }
  /* A proposed host: the host, the server's notice line, and its own approval. */
  function rcardHosts(node,card,refetch,status){
    var hosts=rcardList(card.hosts);
    if(!hosts.length) return;
    node.appendChild(line('rcard-h',RCARD_HOSTS));
    for(var i=0;i<hosts.length;i++){
      (function(hp){
        var row=document.createElement('div'); row.className='rcard-host';
        row.appendChild(line('rcard-host-line',hp.host));
        if(hp.notice) row.appendChild(line('rcard-notice',hp.notice));
        rcardBtn(row,'rcard-host-approve',RCARD_APPROVE,function(){
          rcardPost(node,status,refetch,'hosts/'+encodeURIComponent(rcardText(hp.host))+
            '/approve',undefined);
        });
        node.appendChild(row);
      })(hosts[i]||{});
    }
  }
  /* A requested credential: the host and the inject rule as the settings it is, then its approval.
     The secret itself is never part of this answer. */
  function rcardCredentials(node,card,refetch,status){
    var creds=rcardList(card.credentials);
    if(!creds.length) return;
    node.appendChild(line('rcard-h',RCARD_CREDENTIALS));
    for(var i=0;i<creds.length;i++){
      (function(cr){
        var row=document.createElement('div'); row.className='rcard-cred';
        row.appendChild(line('rcard-host-line',cr.host));
        rcardSettings(row,RCARD_SETTINGS,cr.inject);
        rcardBtn(row,'rcard-cred-approve',RCARD_APPROVE,function(){
          rcardPost(node,status,refetch,'credentials/'+
            encodeURIComponent(rcardText(cr.connectionUuid))+'/approve',
            {injectHash:rcardText(cr.injectHash)});
        });
        node.appendChild(row);
      })(creds[i]||{});
    }
  }

  /* One tap: nothing is disabled until a finger presses it, and a refusal lands in this card's own
     status line. A success reads the card again, which redraws it only if something moved; a conflict
     reads it again too, with its sentence carried onto the new card. */
  function rcardPost(node,status,refetch,path,body){
    rcardBusy(node,true);
    return rcardApi('POST','/'+encodeURIComponent(rcardText(node.getAttribute('data-report-id')))+
      '/'+path,body).then(function(r){
      if(!live()) return;
      if(r&&r.ok){ rcardBusy(node,false); refetch(); return; }
      rcardBusy(node,false);
      status.textContent=rcardSettleRefusal(r,refetch);
    });
  }

  /* One card, from one answer of the report card read. The notice is a sentence a conflict handed to
     the card that replaces the one that was tapped, written into this card's status node. */
  function rcardCard(card,refetch,notice){
    var report=(card&&card.report)||null;
    if(!report) return null;
    var preview=card.preview||null;
    var node=document.createElement('div');
    node.className='entry rcard-card';
    node.setAttribute('data-report-id',rcardText(report.id));
    node.setAttribute('role','group');
    node.setAttribute('aria-label',rcardText(report.title));

    var head=document.createElement('div'); head.className='rcard-head';
    head.appendChild(line('rcard-title',report.title));
    var st=rcardText(report.status);
    head.appendChild(line('rcard-chip rcard-chip-'+st,rcardStatusWord(st)));
    node.appendChild(head);
    if(report.pauseReason) node.appendChild(line('rcard-pause',report.pauseReason));

    var status=line('rcard-status','');
    status.setAttribute('role','status');
    if(preview&&RCARD_PREVIEW_STATES[rcardText(preview.status)]){
      node.appendChild(line('rcard-preview-line',
        rcardText(preview.status)==='queued'?RCARD_PREVIEW_QUEUED:RCARD_PREVIEW_RUNNING));
    }
    /* With no current preview there is nothing to publish: the line says which tap comes first. */
    if(!preview||!preview.current) status.textContent=RCARD_PREVIEW_FIRST;
    node.appendChild(status);
    if(rcardText(notice)) status.textContent=rcardText(notice);

    var actions=document.createElement('div'); actions.className='rcard-actions';
    rcardBtn(actions,'rcard-preview',RCARD_PREVIEW,function(){
      rcardPost(node,status,refetch,'preview',undefined);
    });
    /* The sender account sits directly above the go-live tap: that tap is what sends from it. */
    if(card.sender){
      actions.appendChild(line('rcard-from',rcardFill(RCARD_SEND_FROM,
        {address:rcardText(card.sender.address),kind:rcardKind(card.sender.kind)})));
    }
    if(rcardCanGoLive(report,preview)){
      rcardBtn(actions,'primary rcard-golive',RCARD_GO_LIVE,function(){
        rcardPost(node,status,refetch,'go-live',{previewRunId:rcardText(preview.runId),
          expectedSenderAccountId:card.sender?rcardText(card.sender.accountId):''});
      });
    }
    node.appendChild(actions);

    rcardChanges(node,card);
    if(rcardCanApply(card)){
      var applyRow=document.createElement('div'); applyRow.className='rcard-actions';
      rcardBtn(applyRow,'rcard-apply',RCARD_APPLY,function(){
        /* The revision and the diff hash this card was drawn from, never a fresh read. */
        rcardPost(node,status,refetch,'apply',{expectedRev:card.headRev,
          changesHash:card.changesHash});
      });
      node.appendChild(applyRow);
    }
    rcardSources(node,card,refetch,status);
    rcardRecipients(node,card,refetch,status);
    rcardSteps(node,card,refetch,status);
    rcardHosts(node,card,refetch,status);
    rcardCredentials(node,card,refetch,status);
    if(card.scheduleProposal){
      node.appendChild(line('rcard-schedule-prop',rcardFill(RCARD_SCHEDULE_PROPOSAL,
        {cron:rcardText(card.scheduleProposal.cron),tz:rcardText(card.scheduleProposal.tz)})));
    }
    return node;
  }

  /* ---- loading and mounting --------------------------------------------- */
  /* The key an answer is drawn from: its own JSON, so an unchanged answer redraws nothing. */
  function rcardKey(card){
    try{ return JSON.stringify(card); }catch(e){ return rcardText(card&&card.report&&card.report.id); }
  }
  function rcardDraw(card,opts,notice){
    var report=(card&&card.report)||null;
    if(!report) return null;
    var id=rcardText(report.id);
    var key=rcardKey(card);
    var old=rcardNodes[id];
    if(old&&old.parentNode&&rcardKeys[id]===key){
      rcardNoticeWrite(old,notice);
      rcardPollKeep();
      return old;
    }
    var mine=(opts&&opts.sid)?String(opts.sid):null;
    var refetch=function(text){ return rcardLoad(id,{sid:mine},text); };
    var node=rcardCard(card,refetch,notice);
    if(!node) return null;
    if(old&&old.parentNode){
      old.parentNode.insertBefore(node,old);
      old.parentNode.removeChild(old);
    }else{
      var tr=el('perch-transcript');
      if(!tr) return null;
      tr.appendChild(node);
    }
    rcardNodes[id]=node; rcardKeys[id]=key;
    rcardSid[id]=mine;
    rcardPreview[id]=rcardText(card.preview&&card.preview.status);
    rcardPollReset(id);
    rcardPollKeep();
    return node;
  }
  /* Read one report card and draw it. A read that lands after a session switch draws nothing; a
     notice is carried through to the card the read produces. */
  function rcardLoad(id,opts,notice){
    var myId=rcardText(id);
    if(!RCARD_ID.test(myId)) return null;
    var mine=(opts&&opts.sid)?String(opts.sid):null;
    return rcardApi('GET','/'+encodeURIComponent(myId)+'/card').then(function(r){
      if(!live()) return null;
      if(mine&&current.sid!==mine) return null;
      if(!r||!r.ok||!r.j||!r.j.card) return null;
      return rcardDraw(r.j.card,opts,notice);
    });
  }
  /* The chat's own report ids. The list is ids only: each card is read from the owner's card route,
     which is where the report, the sender, the changes and the proposals come from. */
  function loadReportCards(sid){
    if(!sid) return;
    var mySid=String(sid);
    if(rcardListSid===mySid&&rcardListTimer!==null) return;   /* already on this chat's beat */
    rcardListStop();
    loadReports(mySid);
    rcardListArm(mySid);
  }
  function loadReports(sid){
    var mySid=String(sid);
    perchApi('GET','/interactive/'+encodeURIComponent(mySid)+'/reports').then(function(r){
      if(!live()||current.sid!==mySid) return;
      if(!r||!r.ok||!r.j||!Array.isArray(r.j.reports)) return;
      var ids=[];
      for(var i=0;i<r.j.reports.length;i++){
        var entry=r.j.reports[i];
        if(entry&&typeof entry.id==='string'&&RCARD_ID.test(entry.id)) ids.push(entry.id);
      }
      rcardPrune(ids);
      /* In the list's own order: a report the bot just made lands last, where the eye already is. */
      for(var k=0;k<ids.length;k++){ if(!rcardNodes[ids[k]]) rcardLoad(ids[k],{sid:mySid}); }
    });
  }
  /* A report the list no longer carries is gone from the chat. */
  function rcardPrune(ids){
    var keep={};
    for(var i=0;i<ids.length;i++) keep[ids[i]]=true;
    for(var k in rcardNodes){
      if(keep[k]) continue;
      rcardRemove(rcardNodes[k]);
      rcardForget(k);
    }
    rcardPollKeep();
  }
  function rcardForget(id){
    delete rcardNodes[id]; delete rcardKeys[id]; delete rcardSid[id];
    delete rcardPreview[id]; delete rcardPollCounts[id];
    rcardPollDisarm(id);
  }

  /* ---- the preview poll -------------------------------------------------- */
  /* A card whose preview is queued or running can settle with nobody touching it. Each such card
     reads itself on its own turn, with the same current.sid guard the loads carry; a hidden tab asks
     for nothing and keeps its place; an unchanged answer redraws nothing. */
  function rcardPollWatched(id){
    var node=rcardNodes[id];
    if(!node||!node.parentNode) return false;
    return !!RCARD_PREVIEW_STATES[String(rcardPreview[id]||'')];
  }
  function rcardPollDelay(id){
    var n=Number(rcardPollCounts[id])||0;
    if(n<RCARD_POLL_FAST) return RCARD_POLL_MS;
    if(n===RCARD_POLL_FAST) return RCARD_POLL_SLOW_MS;
    return RCARD_POLL_SLOWEST_MS;
  }
  function rcardPollDisarm(id){
    if(rcardPollTimers[id]===undefined) return;
    clearTimeout(rcardPollTimers[id]);
    delete rcardPollTimers[id];
  }
  function rcardPollArm(id){
    if(rcardPollTimers[id]!==undefined) return;
    if(!rcardPollWatched(id)) return;
    rcardPollTimers[id]=setTimeout(function(){ rcardPollOne(id); },rcardPollDelay(id));
  }
  function rcardPollOne(id){
    rcardPollDisarm(id);
    if(!live()){ rcardPollStop(); return; }
    if(!rcardPollWatched(id)){ rcardPollKeep(); return; }
    var hidden=false;
    try{ hidden=!!document.hidden; }catch(e){ hidden=false; }
    if(hidden){ rcardPollArm(id); return; }
    rcardPollCounts[id]=(Number(rcardPollCounts[id])||0)+1;
    rcardLoad(id,{sid:rcardSid[id]||undefined});
    rcardPollArm(id);
  }
  function rcardPollStop(){
    var ids=Object.keys(rcardPollTimers);
    for(var i=0;i<ids.length;i++) rcardPollDisarm(ids[i]);
  }
  function rcardPollKeep(){
    var ids=Object.keys(rcardNodes);
    for(var i=0;i<ids.length;i++){
      if(rcardPollWatched(ids[i])) rcardPollArm(ids[i]);
      else rcardPollDisarm(ids[i]);
    }
  }
  /* The preview state a card was drawn from moved: the widened gap belonged to the old state. */
  function rcardPollReset(id){
    delete rcardPollCounts[id];
    rcardPollDisarm(id);
    rcardPollArm(id);
  }

  /* ---- the id-list poll -------------------------------------------------- */
  /* Every 8 s while this chat is live and the tab is visible, so a report the bot makes mid-chat
     appears. A hidden tab asks for nothing. One interval per chat: it clears itself the moment the
     chat it was armed for is not the open one, and a session switch clears it outright. */
  function rcardListStop(){
    if(rcardListTimer!==null){ clearInterval(rcardListTimer); rcardListTimer=null; }
    rcardListSid=null;
  }
  function rcardListArm(sid){
    var mySid=String(sid);
    var id=setInterval(function(){
      if(!live()||current.sid!==mySid){
        if(rcardListTimer===id){ clearInterval(id); rcardListTimer=null; rcardListSid=null; }
        return;
      }
      var hidden=false;
      try{ hidden=!!document.hidden; }catch(e){ hidden=false; }
      if(!hidden) loadReports(mySid);
    },RCARD_LIST_MS);
    rcardListTimer=id;
    rcardListSid=mySid;
  }
  /* A session switch: every report card in the transcript is gone, with its poll and the list's. */
  function resetReportCards(){
    rcardListStop();
    for(var k in rcardNodes){
      rcardRemove(rcardNodes[k]);
      rcardForget(k);
    }
    rcardPollStop();
  }
`;
}