
(function(){
  "use strict";
  var RULESET = {
    name: "geode-curated",
    version: "0.2.0",
    snapshot_date: null
  };
  var APP = { name:"GeodeCode", version:"1.0.0", source_url:null };

  function log2(x){ return Math.log(x)/Math.LN2; }
  function entropy(s){
    s = asText(s);
    if(!s) return 0;
    var c={}, n=s.length, i, k, h=0, p;
    for(i=0;i<n;i++){ c[s[i]]=(c[s[i]]||0)+1; }
    for(k in c){ if(c.hasOwnProperty(k)){ p=c[k]/n; h-=p*log2(p); } }
    return h;
  }
  function luhn(num){
    var d=asText(num).replace(/\D/g,"").split("").map(Number), i, x, s=0;
    if(!(d.length>=13 && d.length<=19)) return false;
    for(i=0;i<d.length;i++){ x=d[d.length-1-i]; if(i%2===1){ x*=2; if(x>9) x-=9; } s+=x; }
    return s%10===0;
  }
  var GTLD={com:1,org:1,net:1,io:1,dev:1,ai:1,co:1,edu:1,gov:1,mil:1,info:1,biz:1,app:1,xyz:1,
    tech:1,me:1,tv:1,cc:1,cloud:1,page:1,sh:1,gg:1,to:1,design:1,email:1,link:1};
  function validTld(t){ t=t.toLowerCase(); return t.length===2 || GTLD.hasOwnProperty(t); }

  var PLACEHOLDER=/(changeme|your[_-]?(api[_-]?)?key|example\.(com|org|net)|xxxx+|placeholder|redacted|dummy|sample|test[_-]?key|\*{4,}|\.{3,}|<[^>]{1,40}>|\{\{|\$\{)/i;

  var TIER1=[
    {name:"aws_akia",       label:"AWS",    re:/\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b/, allow:[/^AKIAIOSFODNN7EXAMPLE$/]},
    {name:"github_token",   label:"TOKEN",  re:/\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/, allow:[]},
    {name:"gitlab_pat",     label:"TOKEN",  re:/\bglpat-[A-Za-z0-9_\-]{20}\b/, allow:[]},
    {name:"stripe_live",    label:"KEY",    re:/\b[rsp]k_live_[A-Za-z0-9]{20,}\b/, allow:[]},
    {name:"google_api",     label:"KEY",    re:/\bAIza[0-9A-Za-z_\-]{35}\b/, allow:[]},
    {name:"anthropic_key",  label:"KEY",    re:/\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93}AA\b/, allow:[]},
    {name:"slack_token",    label:"TOKEN",  re:/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, allow:[]},
    {name:"jwt",            label:"JWT",    re:/\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}\b/, allow:[]},
    {name:"private_key_pem",label:"KEY",    re:/-----BEGIN [A-Z ]*PRIVATE KEY-----/, allow:[]},
    {name:"db_url_cred",    label:"CRED",   re:/\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/]+:[^\s:@/]+@/, allow:[]},
    {name:"npm_token",      label:"TOKEN",  re:/\bnpm_[A-Za-z0-9]{36}\b/, allow:[]},
    {name:"sendgrid",       label:"KEY",    re:/\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/, allow:[]},
    {name:"digitalocean",   label:"TOKEN",  re:/\b(?:dop|doo|dor)_v1_[a-f0-9]{64}\b/, allow:[]},
    {name:"doppler",        label:"TOKEN",  re:/\bdp\.pt\.[A-Za-z0-9]{43}\b/, allow:[]},
    {name:"linear_key",     label:"KEY",    re:/\blin_api_[A-Za-z0-9]{40}\b/, allow:[]},
    {name:"huggingface",    label:"TOKEN",  re:/\bhf_[a-zA-Z]{34}\b/, allow:[]},
    {name:"grafana_sa",     label:"TOKEN",  re:/\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b/, allow:[]},
    {name:"databricks",     label:"TOKEN",  re:/\bdapi[a-f0-9]{32}(?:-\d)?\b/, allow:[]},
    {name:"age_key",        label:"KEY",    re:/\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b/, allow:[]},
    {name:"generic_40hex",  label:"SECRET", re:/(?<![0-9a-fA-F])[0-9a-f]{40}(?![0-9a-fA-F])/, allow:[]}
  ];
  var EMAIL=/\b[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+)\.([A-Za-z]{2,})\b/;
  var SSN=/\b\d{3}-\d{2}-\d{4}\b/, SSN_CTX=["ssn","social security","tax","taxpayer"];
  var CC=/\b(?:\d[ -]?){13,19}\b/, CC_CTX=["card","credit","visa","master","amex","payment","cc"];
  var IP=/\b(?:\d{1,3}\.){3}\d{1,3}\b/, IP_CTX=["ip","host","server","addr","bind","listen"];
  var KV=/[A-Za-z0-9_.\-]*(?:secret|token|passwd|password|api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|credential|passphrase)(?![a-z])[A-Za-z0-9_.\-]*['"]?\s*[:=]\s*['"]?([^\s'"`,;]{8,})/i;

  function asText(v){
    if(typeof v==="string") return v;
    if(v===null || v===undefined) return "";
    if(typeof v==="number" || typeof v==="boolean" || typeof v==="bigint") return String(v);
    return "";
  }
  function asList(v){ return Array.isArray(v) ? v : []; }

  function some(arr,fn){ for(var i=0;i<arr.length;i++){ if(fn(arr[i])) return true; } return false; }

  var CTX_CACHE={};
  function ctxRe(words){
    var k=words.join("|");
    if(!CTX_CACHE[k]) CTX_CACHE[k]=new RegExp("\\b(?:"+k+")","i");
    return CTX_CACHE[k];
  }
  function hasContext(low, words){ return ctxRe(words).test(low); }

  var MAX_SCAN_LINE = 4 * 1024 * 1024;
  var KV_TRIGGERS = ["secret","token","passwd","password","api_key","apikey","api-key",
    "access_key","accesskey","access-key","secret_key","secretkey","secret-key",
    "private_key","privatekey","private-key","client_secret","clientsecret","client-secret",
    "auth_token","authtoken","auth-token","credential","passphrase"];
  function kvMayMatch(low){
    for(var i=0;i<KV_TRIGGERS.length;i++){ if(low.indexOf(KV_TRIGGERS[i])>=0) return true; }
    return false;
  }

  var RULEPACK = [
{"id":"1password-secret-key","re":"\\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\\b","fl":"","kw":["a3-"],"lb":"PW","ho":false,"co":false},
{"id":"1password-service-account-token","re":"ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}","fl":"","kw":["ops_"],"lb":"PW","ho":false,"co":false},
{"id":"adafruit-api-key","re":"[\\w.-]{0,50}?(?:adafruit)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9_-]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["adafruit"],"lb":"KEY","ho":false,"co":false},
{"id":"adobe-client-id","re":"[\\w.-]{0,50}?(?:adobe)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-f0-9]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["adobe"],"lb":"ID","ho":false,"co":false},
{"id":"adobe-client-secret","re":"\\b(p8e-[a-z0-9]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["p8e-"],"lb":"SECRET","ho":true,"co":false},
{"id":"age-secret-key","re":"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}","fl":"","kw":["age-secret-key-1"],"lb":"SECRET","ho":false,"co":false},
{"id":"airtable-api-key","re":"[\\w.-]{0,50}?(?:airtable)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{17})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["airtable"],"lb":"KEY","ho":false,"co":false},
{"id":"airtable-personnal-access-token","re":"\\b(patA-Za-z0-9{14}\\.[a-f0-9]{64})\\b","fl":"","kw":["airtable"],"lb":"TOKEN","ho":false,"co":false},
{"id":"algolia-api-key","re":"[\\w.-]{0,50}?(?:algolia)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["algolia"],"lb":"KEY","ho":false,"co":false},
{"id":"alibaba-access-key-id","re":"\\b(LTAI[a-z0-9]{20})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["ltai"],"lb":"ID","ho":true,"co":false},
{"id":"alibaba-secret-key","re":"[\\w.-]{0,50}?(?:alibaba)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{30})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["alibaba"],"lb":"SECRET","ho":false,"co":false},
{"id":"anthropic-admin-api-key","re":"\\b(sk-ant-admin01-[a-zA-Z0-9_\\-]{93}AA)(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["sk-ant-admin01"],"lb":"KEY","ho":false,"co":false},
{"id":"anthropic-api-key","re":"\\b(sk-ant-api03-[a-zA-Z0-9_\\-]{93}AA)(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["sk-ant-api03"],"lb":"KEY","ho":false,"co":false},
{"id":"artifactory-api-key","re":"\\bAKCp[A-Za-z0-9]{69}\\b","fl":"","kw":["akcp"],"lb":"KEY","ho":false,"co":false},
{"id":"artifactory-reference-token","re":"\\bcmVmd[A-Za-z0-9]{59}\\b","fl":"","kw":["cmvmd"],"lb":"TOKEN","ho":false,"co":false},
{"id":"asana-client-id","re":"[\\w.-]{0,50}?(?:asana)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([0-9]{16})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["asana"],"lb":"ID","ho":false,"co":false},
{"id":"asana-client-secret","re":"[\\w.-]{0,50}?(?:asana)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["asana"],"lb":"SECRET","ho":false,"co":false},
{"id":"aws-access-token","re":"\\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\\b","fl":"","kw":["a3t","akia","asia","abia","acca"],"lb":"TOKEN","ho":false,"co":false},
{"id":"aws-amazon-bedrock-api-key-long-lived","re":"\\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["absk"],"lb":"KEY","ho":false,"co":false},
{"id":"aws-amazon-bedrock-api-key-short-lived","re":"bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t","fl":"","kw":["bedrock-api-key-"],"lb":"KEY","ho":false,"co":false},
{"id":"azure-ad-client-secret","re":"(?:^|[\\\\'\"`\\s>=:(,)])([a-zA-Z0-9_~.]{3}\\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\\\'\"`\\s<),])","fl":"","kw":["q~"],"lb":"SECRET","ho":false,"co":false},
{"id":"beamer-api-token","re":"[\\w.-]{0,50}?(?:beamer)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}(b_[a-z0-9=_\\-]{44})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["beamer"],"lb":"TOKEN","ho":false,"co":false},
{"id":"bitbucket-client-id","re":"[\\w.-]{0,50}?(?:bitbucket)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["bitbucket"],"lb":"ID","ho":false,"co":false},
{"id":"bitbucket-client-secret","re":"[\\w.-]{0,50}?(?:bitbucket)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9=_\\-]{64})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["bitbucket"],"lb":"SECRET","ho":false,"co":false},
{"id":"bittrex-access-key","re":"[\\w.-]{0,50}?(?:bittrex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["bittrex"],"lb":"KEY","ho":false,"co":false},
{"id":"bittrex-secret-key","re":"[\\w.-]{0,50}?(?:bittrex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["bittrex"],"lb":"SECRET","ho":false,"co":false},
{"id":"clickhouse-cloud-api-secret-key","re":"\\b(4b1d[A-Za-z0-9]{38})\\b","fl":"","kw":["4b1d"],"lb":"SECRET","ho":false,"co":false},
{"id":"clojars-api-token","re":"CLOJARS_[a-z0-9]{60}","fl":"i","kw":["clojars_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"cloudflare-api-key","re":"[\\w.-]{0,50}?(?:cloudflare)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9_-]{40})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["cloudflare"],"lb":"KEY","ho":false,"co":false},
{"id":"cloudflare-global-api-key","re":"[\\w.-]{0,50}?(?:cloudflare)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-f0-9]{37})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["cloudflare"],"lb":"KEY","ho":false,"co":false},
{"id":"cloudflare-origin-ca-key","re":"\\b(v1\\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["cloudflare","v1.0-"],"lb":"KEY","ho":false,"co":false},
{"id":"codecov-access-token","re":"[\\w.-]{0,50}?(?:codecov)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["codecov"],"lb":"TOKEN","ho":false,"co":false},
{"id":"cohere-api-token","re":"[\\w.-]{0,100}?(?:(?:cohere|CO_API_KEY)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-zA-Z0-9]{40})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["cohere","co_api_key"],"lb":"TOKEN","ho":true,"co":true},
{"id":"coinbase-access-token","re":"[\\w.-]{0,50}?(?:coinbase)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9_-]{64})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["coinbase"],"lb":"TOKEN","ho":false,"co":false},
{"id":"confluent-access-token","re":"[\\w.-]{0,50}?(?:confluent)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{16})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["confluent"],"lb":"TOKEN","ho":false,"co":false},
{"id":"confluent-secret-key","re":"[\\w.-]{0,50}?(?:confluent)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{64})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["confluent"],"lb":"SECRET","ho":false,"co":false},
{"id":"contentful-delivery-api-token","re":"[\\w.-]{0,50}?(?:contentful)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9=_\\-]{43})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["contentful"],"lb":"TOKEN","ho":false,"co":false},
{"id":"curl-auth-header","re":"\\bcurl\\b(?:.*?|.*?(?:[\\r\\n]{1,2}.*?){1,5})[ \\t\\n\\r](?:-H|--header)(?:=|[ \\t]{0,5})(?:\"(?:Authorization:[ \\t]{0,5}(?:Basic[ \\t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \\t]([\\w=~@.+/-]{8,})|([\\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \\t]{0,5}([\\w=~@.+/-]{8,}))\"|'(?:Authorization:[ \\t]{0,5}(?:Basic[ \\t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \\t]([\\w=~@.+/-]{8,})|([\\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \\t]{0,5}([\\w=~@.+/-]{8,}))')(?:\\B|\\s|\\z)","fl":"i","kw":["curl"],"lb":"KEY","ho":true,"co":false},
{"id":"curl-auth-user","re":"\\bcurl\\b(?:.*|.*(?:[\\r\\n]{1,2}.*){1,5})[ \\t\\n\\r](?:-u|--user)(?:=|[ \\t]{0,5})(\"(:[^\"]{3,}|[^:\"]{3,}:|[^:\"]{3,}:[^\"]{3,})\"|'([^:']{3,}:[^']{3,})'|((?:\"[^\"]{3,}\"|'[^']{3,}'|[\\w$@.-]+):(?:\"[^\"]{3,}\"|'[^']{3,}'|[\\w${}@.-]+)))(?:\\s|\\z)","fl":"","kw":["curl"],"lb":"KEY","ho":false,"co":false},
{"id":"databricks-api-token","re":"\\b(dapi[a-f0-9]{32}(?:-\\d)?)(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["dapi"],"lb":"TOKEN","ho":false,"co":false},
{"id":"datadog-access-token","re":"[\\w.-]{0,50}?(?:datadog)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{40})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["datadog"],"lb":"TOKEN","ho":false,"co":false},
{"id":"defined-networking-api-token","re":"[\\w.-]{0,50}?(?:dnkey)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}(dnkey-[a-z0-9=_\\-]{26}-[a-z0-9=_\\-]{52})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["dnkey"],"lb":"TOKEN","ho":false,"co":false},
{"id":"digitalocean-access-token","re":"\\b(doo_v1_[a-f0-9]{64})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["doo_v1_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"digitalocean-pat","re":"\\b(dop_v1_[a-f0-9]{64})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["dop_v1_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"digitalocean-refresh-token","re":"\\b(dor_v1_[a-f0-9]{64})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["dor_v1_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"discord-api-token","re":"[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-f0-9]{64})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["discord"],"lb":"TOKEN","ho":false,"co":false},
{"id":"discord-client-id","re":"[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([0-9]{18})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["discord"],"lb":"ID","ho":false,"co":false},
{"id":"discord-client-secret","re":"[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["discord"],"lb":"SECRET","ho":false,"co":false},
{"id":"doppler-api-token","re":"dp\\.pt\\.[a-z0-9]{43}","fl":"i","kw":["dp.pt."],"lb":"TOKEN","ho":true,"co":false},
{"id":"droneci-access-token","re":"[\\w.-]{0,50}?(?:droneci)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["droneci"],"lb":"TOKEN","ho":false,"co":false},
{"id":"dropbox-api-token","re":"[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{15})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["dropbox"],"lb":"TOKEN","ho":false,"co":false},
{"id":"dropbox-long-lived-api-token","re":"[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\\-_=]{43})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["dropbox"],"lb":"TOKEN","ho":false,"co":false},
{"id":"dropbox-short-lived-api-token","re":"[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}(sl\\.[a-z0-9\\-=_]{135})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["dropbox"],"lb":"TOKEN","ho":false,"co":false},
{"id":"duffel-api-token","re":"duffel_(?:test|live)_[a-z0-9_\\-=]{43}","fl":"i","kw":["duffel_"],"lb":"TOKEN","ho":true,"co":false},
{"id":"dynatrace-api-token","re":"dt0c01\\.[a-z0-9]{24}\\.[a-z0-9]{64}","fl":"i","kw":["dt0c01."],"lb":"TOKEN","ho":true,"co":false},
{"id":"easypost-api-token","re":"\\bEZAK[a-z0-9]{54}\\b","fl":"i","kw":["ezak"],"lb":"TOKEN","ho":true,"co":false},
{"id":"easypost-test-api-token","re":"\\bEZTK[a-z0-9]{54}\\b","fl":"i","kw":["eztk"],"lb":"TOKEN","ho":true,"co":false},
{"id":"facebook-access-token","re":"\\b(\\d{15,16}(\\||%)[0-9a-z\\-_]{27,40})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["facebook"],"lb":"TOKEN","ho":false,"co":false},
{"id":"facebook-page-access-token","re":"\\b(EAA[MC][a-z0-9]{100,})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["eaam","eaac"],"lb":"TOKEN","ho":true,"co":false},
{"id":"facebook-secret","re":"[\\w.-]{0,50}?(?:facebook)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-f0-9]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["facebook"],"lb":"SECRET","ho":false,"co":false},
{"id":"fastly-api-token","re":"[\\w.-]{0,50}?(?:fastly)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["fastly"],"lb":"TOKEN","ho":false,"co":false},
{"id":"finicity-api-token","re":"[\\w.-]{0,50}?(?:finicity)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-f0-9]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["finicity"],"lb":"TOKEN","ho":false,"co":false},
{"id":"finicity-client-secret","re":"[\\w.-]{0,50}?(?:finicity)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{20})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["finicity"],"lb":"SECRET","ho":false,"co":false},
{"id":"finnhub-access-token","re":"[\\w.-]{0,50}?(?:finnhub)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{20})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["finnhub"],"lb":"TOKEN","ho":false,"co":false},
{"id":"flickr-access-token","re":"[\\w.-]{0,50}?(?:flickr)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["flickr"],"lb":"TOKEN","ho":false,"co":false},
{"id":"flutterwave-encryption-key","re":"FLWSECK_TEST-[a-h0-9]{12}","fl":"i","kw":["flwseck_test"],"lb":"KEY","ho":true,"co":false},
{"id":"flutterwave-public-key","re":"FLWPUBK_TEST-[a-h0-9]{32}-X","fl":"i","kw":["flwpubk_test"],"lb":"KEY","ho":true,"co":false},
{"id":"flutterwave-secret-key","re":"FLWSECK_TEST-[a-h0-9]{32}-X","fl":"i","kw":["flwseck_test"],"lb":"SECRET","ho":true,"co":false},
{"id":"flyio-access-token","re":"\\b((?:fo1_[\\w-]{43}|fm1[ar]_[a-zA-Z0-9+\\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\\/]{100,}={0,3}))(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["fo1_","fm1","fm2_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"frameio-api-token","re":"fio-u-[a-z0-9\\-_=]{64}","fl":"i","kw":["fio-u-"],"lb":"TOKEN","ho":true,"co":false},
{"id":"freemius-secret-key","re":"[\"']secret_key[\"']\\s*=>\\s*[\"'](sk_[\\S]{29})[\"']","fl":"i","kw":["secret_key"],"lb":"SECRET","ho":false,"co":false},
{"id":"freshbooks-access-token","re":"[\\w.-]{0,50}?(?:freshbooks)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{64})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["freshbooks"],"lb":"TOKEN","ho":false,"co":false},
{"id":"gcp-api-key","re":"\\b(AIza[\\w-]{35})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["aiza"],"lb":"KEY","ho":false,"co":false},
{"id":"github-app-token","re":"(?:ghu|ghs)_[0-9a-zA-Z]{36}","fl":"","kw":["ghu_","ghs_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"github-fine-grained-pat","re":"github_pat_\\w{82}","fl":"","kw":["github_pat_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"github-oauth","re":"gho_[0-9a-zA-Z]{36}","fl":"","kw":["gho_"],"lb":"KEY","ho":false,"co":false},
{"id":"github-pat","re":"ghp_[0-9a-zA-Z]{36}","fl":"","kw":["ghp_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"github-refresh-token","re":"ghr_[0-9a-zA-Z]{36}","fl":"","kw":["ghr_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"gitlab-cicd-job-token","re":"glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}","fl":"","kw":["glcbt-"],"lb":"TOKEN","ho":false,"co":false},
{"id":"gitlab-deploy-token","re":"gldt-[0-9a-zA-Z_\\-]{20}","fl":"","kw":["gldt-"],"lb":"TOKEN","ho":false,"co":false},
{"id":"gitlab-feature-flag-client-token","re":"glffct-[0-9a-zA-Z_\\-]{20}","fl":"","kw":["glffct-"],"lb":"TOKEN","ho":false,"co":false},
{"id":"gitlab-feed-token","re":"glft-[0-9a-zA-Z_\\-]{20}","fl":"","kw":["glft-"],"lb":"TOKEN","ho":false,"co":false},
{"id":"gitlab-incoming-mail-token","re":"glimt-[0-9a-zA-Z_\\-]{25}","fl":"","kw":["glimt-"],"lb":"TOKEN","ho":false,"co":false},
{"id":"gitlab-kubernetes-agent-token","re":"glagent-[0-9a-zA-Z_\\-]{50}","fl":"","kw":["glagent-"],"lb":"TOKEN","ho":false,"co":false},
{"id":"gitlab-oauth-app-secret","re":"gloas-[0-9a-zA-Z_\\-]{64}","fl":"","kw":["gloas-"],"lb":"SECRET","ho":false,"co":false},
{"id":"gitlab-pat","re":"glpat-[\\w-]{20}","fl":"","kw":["glpat-"],"lb":"TOKEN","ho":false,"co":false},
{"id":"gitlab-pat-routable","re":"\\bglpat-[0-9a-zA-Z_-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b","fl":"","kw":["glpat-"],"lb":"TOKEN","ho":false,"co":false},
{"id":"gitlab-ptt","re":"glptt-[0-9a-f]{40}","fl":"","kw":["glptt-"],"lb":"KEY","ho":false,"co":false},
{"id":"gitlab-rrt","re":"GR1348941[\\w-]{20}","fl":"","kw":["gr1348941"],"lb":"KEY","ho":false,"co":false},
{"id":"gitlab-runner-authentication-token","re":"glrt-[0-9a-zA-Z_\\-]{20}","fl":"","kw":["glrt-"],"lb":"TOKEN","ho":false,"co":false},
{"id":"gitlab-runner-authentication-token-routable","re":"\\bglrt-t\\d_[0-9a-zA-Z_\\-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b","fl":"","kw":["glrt-"],"lb":"TOKEN","ho":false,"co":false},
{"id":"gitlab-scim-token","re":"glsoat-[0-9a-zA-Z_\\-]{20}","fl":"","kw":["glsoat-"],"lb":"TOKEN","ho":false,"co":false},
{"id":"gitlab-session-cookie","re":"_gitlab_session=[0-9a-z]{32}","fl":"","kw":["_gitlab_session="],"lb":"KEY","ho":false,"co":false},
{"id":"gitter-access-token","re":"[\\w.-]{0,50}?(?:gitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9_-]{40})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["gitter"],"lb":"TOKEN","ho":false,"co":false},
{"id":"gocardless-api-token","re":"[\\w.-]{0,50}?(?:gocardless)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}(live_[a-z0-9\\-_=]{40})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["live_","gocardless"],"lb":"TOKEN","ho":true,"co":false},
{"id":"grafana-api-key","re":"\\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["eyjrijoi"],"lb":"KEY","ho":false,"co":false},
{"id":"grafana-cloud-api-token","re":"\\b(glc_[A-Za-z0-9+/]{32,400}={0,3})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["glc_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"grafana-service-account-token","re":"\\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["glsa_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"harness-api-key","re":"(?:pat|sat)\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{20}","fl":"","kw":["pat.","sat."],"lb":"KEY","ho":false,"co":false},
{"id":"hashicorp-tf-password","re":"[\\w.-]{0,50}?(?:administrator_login_password|password)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}(\"[a-z0-9=_\\-]{8,20}\")(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["administrator_login_password","password"],"lb":"PW","ho":false,"co":false},
{"id":"heroku-api-key","re":"[\\w.-]{0,50}?(?:heroku)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["heroku"],"lb":"KEY","ho":false,"co":false},
{"id":"heroku-api-key-v2","re":"\\b((HRKU-AA[0-9a-zA-Z_-]{58}))(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["hrku-aa"],"lb":"KEY","ho":false,"co":false},
{"id":"hubspot-api-key","re":"[\\w.-]{0,50}?(?:hubspot)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["hubspot"],"lb":"KEY","ho":false,"co":false},
{"id":"huggingface-access-token","re":"\\b(hf_(?:[a-z]{34}))(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["hf_"],"lb":"TOKEN","ho":true,"co":false},
{"id":"huggingface-organization-api-token","re":"\\b(api_org_(?:[a-z]{34}))(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["api_org_"],"lb":"TOKEN","ho":true,"co":false},
{"id":"infracost-api-token","re":"\\b(ico-[a-zA-Z0-9]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["ico-"],"lb":"TOKEN","ho":false,"co":false},
{"id":"intercom-api-key","re":"[\\w.-]{0,50}?(?:intercom)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9=_\\-]{60})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["intercom"],"lb":"KEY","ho":false,"co":false},
{"id":"intra42-client-secret","re":"\\b(s-s4t2(?:ud|af)-[abcdef0123456789]{64})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["intra","s-s4t2ud-","s-s4t2af-"],"lb":"SECRET","ho":true,"co":false},
{"id":"jfrog-api-key","re":"[\\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{73})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["jfrog","artifactory","bintray","xray"],"lb":"KEY","ho":false,"co":false},
{"id":"jfrog-identity-token","re":"[\\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{64})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["jfrog","artifactory","bintray","xray"],"lb":"TOKEN","ho":false,"co":false},
{"id":"jwt","re":"\\b(ey[a-zA-Z0-9]{17,}\\.ey[a-zA-Z0-9\\/\\\\_-]{17,}\\.(?:[a-zA-Z0-9\\/\\\\_-]{10,}={0,2})?)(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["ey"],"lb":"TOKEN","ho":false,"co":false},
{"id":"jwt-base64","re":"\\bZXlK(?:(?<alg>aGJHY2lPaU)|(?<apu>aGNIVWlPaU)|(?<apv>aGNIWWlPaU)|(?<aud>aGRXUWlPaU)|(?<b64>aU5qUWlP)|(?<crit>amNtbDBJanBi)|(?<cty>amRIa2lPaU)|(?<epk>bGNHc2lPbn)|(?<enc>bGJtTWlPaU)|(?<jku>cWEzVWlPaU)|(?<jwk>cWQyc2lPb)|(?<iss>cGMzTWlPaU)|(?<iv>cGRpSTZJ)|(?<kid>cmFXUWlP)|(?<key_ops>clpYbGZiM0J6SWpwY)|(?<kty>cmRIa2lPaUp)|(?<nonce>dWIyNWpaU0k2)|(?<p2c>d01tTWlP)|(?<p2s>d01uTWlPaU)|(?<ppt>d2NIUWlPaU)|(?<sub>emRXSWlPaU)|(?<svt>emRuUWlP)|(?<tag>MFlXY2lPaU)|(?<typ>MGVYQWlPaUp)|(?<url>MWNtd2l)|(?<use>MWMyVWlPaUp)|(?<ver>MlpYSWlPaU)|(?<version>MlpYSnphVzl1SWpv)|(?<x>NElqb2)|(?<x5c>NE5XTWlP)|(?<x5t>NE5YUWlPaU)|(?<x5ts256>NE5YUWpVekkxTmlJNkl)|(?<x5u>NE5YVWlPaU)|(?<zip>NmFYQWlPaU))[a-zA-Z0-9\\/\\\\_+\\-\\r\\n]{40,}={0,2}","fl":"","kw":["zxlk"],"lb":"TOKEN","ho":false,"co":false},
{"id":"kraken-access-token","re":"[\\w.-]{0,50}?(?:kraken)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9\\/=_\\+\\-]{80,90})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["kraken"],"lb":"TOKEN","ho":false,"co":false},
{"id":"kucoin-access-token","re":"[\\w.-]{0,50}?(?:kucoin)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-f0-9]{24})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["kucoin"],"lb":"TOKEN","ho":false,"co":false},
{"id":"kucoin-secret-key","re":"[\\w.-]{0,50}?(?:kucoin)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["kucoin"],"lb":"SECRET","ho":false,"co":false},
{"id":"launchdarkly-access-token","re":"[\\w.-]{0,50}?(?:launchdarkly)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9=_\\-]{40})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["launchdarkly"],"lb":"TOKEN","ho":false,"co":false},
{"id":"linear-api-key","re":"lin_api_[a-z0-9]{40}","fl":"i","kw":["lin_api_"],"lb":"KEY","ho":true,"co":false},
{"id":"linear-client-secret","re":"[\\w.-]{0,50}?(?:linear)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-f0-9]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["linear"],"lb":"SECRET","ho":false,"co":false},
{"id":"linkedin-client-id","re":"[\\w.-]{0,50}?(?:linked[_-]?in)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{14})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["linkedin","linked_in","linked-in"],"lb":"ID","ho":false,"co":false},
{"id":"linkedin-client-secret","re":"[\\w.-]{0,50}?(?:linked[_-]?in)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{16})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["linkedin","linked_in","linked-in"],"lb":"SECRET","ho":false,"co":false},
{"id":"lob-api-key","re":"[\\w.-]{0,50}?(?:lob)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}((live|test)_[a-f0-9]{35})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["test_","live_"],"lb":"KEY","ho":false,"co":false},
{"id":"lob-pub-api-key","re":"[\\w.-]{0,50}?(?:lob)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}((test|live)_pub_[a-f0-9]{31})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["test_pub","live_pub","_pub"],"lb":"KEY","ho":false,"co":false},
{"id":"looker-client-id","re":"[\\w.-]{0,50}?(?:looker)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{20})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["looker"],"lb":"ID","ho":false,"co":false},
{"id":"looker-client-secret","re":"[\\w.-]{0,50}?(?:looker)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{24})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["looker"],"lb":"SECRET","ho":false,"co":false},
{"id":"mailchimp-api-key","re":"[\\w.-]{0,50}?(?:MailchimpSDK.initialize|mailchimp)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-f0-9]{32}-us\\d\\d)(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["mailchimp"],"lb":"KEY","ho":false,"co":false},
{"id":"mailgun-private-api-token","re":"[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}(key-[a-f0-9]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["mailgun"],"lb":"TOKEN","ho":false,"co":false},
{"id":"mailgun-pub-key","re":"[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}(pubkey-[a-f0-9]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["mailgun"],"lb":"KEY","ho":false,"co":false},
{"id":"mailgun-signing-key","re":"[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["mailgun"],"lb":"KEY","ho":false,"co":false},
{"id":"mapbox-api-token","re":"[\\w.-]{0,50}?(?:mapbox)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}(pk\\.[a-z0-9]{60}\\.[a-z0-9]{22})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["mapbox"],"lb":"TOKEN","ho":false,"co":false},
{"id":"mattermost-access-token","re":"[\\w.-]{0,50}?(?:mattermost)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{26})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["mattermost"],"lb":"TOKEN","ho":false,"co":false},
{"id":"maxmind-license-key","re":"\\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["_mmk"],"lb":"KEY","ho":false,"co":false},
{"id":"messagebird-api-token","re":"[\\w.-]{0,50}?(?:message[_-]?bird)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{25})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["messagebird","message-bird","message_bird"],"lb":"TOKEN","ho":false,"co":false},
{"id":"messagebird-client-id","re":"[\\w.-]{0,50}?(?:message[_-]?bird)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["messagebird","message-bird","message_bird"],"lb":"ID","ho":false,"co":false},
{"id":"microsoft-teams-webhook","re":"https://[a-z0-9]+\\.webhook\\.office\\.com/webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}","fl":"","kw":["webhook.office.com","webhookb2","incomingwebhook"],"lb":"KEY","ho":false,"co":false},
{"id":"netlify-access-token","re":"[\\w.-]{0,50}?(?:netlify)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9=_\\-]{40,46})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["netlify"],"lb":"TOKEN","ho":false,"co":false},
{"id":"new-relic-browser-api-token","re":"[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}(NRJS-[a-f0-9]{19})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["nrjs-"],"lb":"TOKEN","ho":false,"co":false},
{"id":"new-relic-insert-key","re":"[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}(NRII-[a-z0-9-]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["nrii-"],"lb":"KEY","ho":false,"co":false},
{"id":"new-relic-user-api-id","re":"[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{64})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["new-relic","newrelic","new_relic"],"lb":"ID","ho":false,"co":false},
{"id":"new-relic-user-api-key","re":"[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}(NRAK-[a-z0-9]{27})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["nrak"],"lb":"KEY","ho":false,"co":false},
{"id":"notion-api-token","re":"\\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["ntn_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"npm-access-token","re":"\\b(npm_[a-z0-9]{36})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["npm_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"nuget-config-password","re":"<add key=\\\"(?:(?:ClearText)?Password)\\\"\\s*value=\\\"(.{8,})\\\"\\s*/>","fl":"i","kw":["<add key="],"lb":"PW","ho":false,"co":false},
{"id":"nytimes-access-token","re":"[\\w.-]{0,50}?(?:nytimes|new-york-times,|newyorktimes)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["nytimes","new-york-times","newyorktimes"],"lb":"TOKEN","ho":false,"co":false},
{"id":"octopus-deploy-api-key","re":"\\b(API-[A-Z0-9]{26})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["api-"],"lb":"KEY","ho":false,"co":false},
{"id":"openai-api-key","re":"\\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["t3blbkfj"],"lb":"KEY","ho":false,"co":false},
{"id":"openshift-user-token","re":"\\b(sha256~[\\w-]{43})(?:[^\\w-]|\\z)","fl":"","kw":["sha256~"],"lb":"TOKEN","ho":false,"co":false},
{"id":"perplexity-api-key","re":"\\b(pplx-[a-zA-Z0-9]{48})(?:[`'\"\\s;]|\\\\[nr]|$|\\b)","fl":"","kw":["pplx-"],"lb":"KEY","ho":false,"co":false},
{"id":"plaid-api-token","re":"[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["plaid"],"lb":"TOKEN","ho":false,"co":false},
{"id":"plaid-client-id","re":"[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{24})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["plaid"],"lb":"ID","ho":false,"co":false},
{"id":"plaid-secret-key","re":"[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{30})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["plaid"],"lb":"SECRET","ho":false,"co":false},
{"id":"planetscale-api-token","re":"\\b(pscale_tkn_[\\w=\\.-]{32,64})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["pscale_tkn_"],"lb":"TOKEN","ho":true,"co":false},
{"id":"planetscale-oauth-token","re":"\\b(pscale_oauth_[\\w=\\.-]{32,64})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["pscale_oauth_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"planetscale-password","re":"\\b(pscale_pw_[\\w=\\.-]{32,64})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["pscale_pw_"],"lb":"PW","ho":true,"co":false},
{"id":"postman-api-token","re":"\\b(PMAK-[a-f0-9]{24}\\-[a-f0-9]{34})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["pmak-"],"lb":"TOKEN","ho":true,"co":false},
{"id":"prefect-api-token","re":"\\b(pnu_[a-zA-Z0-9]{36})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["pnu_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"private-key","re":"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\\s\\S-]{64,}?KEY(?: BLOCK)?-----","fl":"i","kw":["-----begin"],"lb":"KEY","ho":false,"co":false},
{"id":"privateai-api-token","re":"[\\w.-]{0,100}?(?:(?:private[_-]?ai)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{32})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["privateai","private_ai","private-ai"],"lb":"TOKEN","ho":true,"co":true},
{"id":"pulumi-api-token","re":"\\b(pul-[a-f0-9]{40})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["pul-"],"lb":"TOKEN","ho":false,"co":false},
{"id":"pypi-upload-token","re":"pypi-AgEIcHlwaS5vcmc[\\w-]{50,1000}","fl":"","kw":["pypi-ageichlwas5vcmc"],"lb":"TOKEN","ho":false,"co":false},
{"id":"rapidapi-access-token","re":"[\\w.-]{0,50}?(?:rapidapi)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9_-]{50})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["rapidapi"],"lb":"TOKEN","ho":false,"co":false},
{"id":"readme-api-token","re":"\\b(rdme_[a-z0-9]{70})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["rdme_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"rubygems-api-token","re":"\\b(rubygems_[a-f0-9]{48})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["rubygems_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"scalingo-api-token","re":"\\b(tk-us-[\\w-]{48})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["tk-us-"],"lb":"TOKEN","ho":false,"co":false},
{"id":"sendbird-access-id","re":"[\\w.-]{0,50}?(?:sendbird)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["sendbird"],"lb":"ID","ho":false,"co":false},
{"id":"sendbird-access-token","re":"[\\w.-]{0,50}?(?:sendbird)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-f0-9]{40})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["sendbird"],"lb":"TOKEN","ho":false,"co":false},
{"id":"sendgrid-api-token","re":"\\b(SG\\.[a-z0-9=_\\-\\.]{66})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["sg."],"lb":"TOKEN","ho":true,"co":false},
{"id":"sendinblue-api-token","re":"\\b(xkeysib-[a-f0-9]{64}\\-[a-z0-9]{16})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["xkeysib-"],"lb":"TOKEN","ho":true,"co":false},
{"id":"sentry-access-token","re":"[\\w.-]{0,50}?(?:sentry)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-f0-9]{64})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["sentry"],"lb":"TOKEN","ho":false,"co":false},
{"id":"sentry-org-token","re":"\\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}(?:[^a-zA-Z0-9+/]|\\z)","fl":"","kw":["sntrys_eyjpyxqio"],"lb":"TOKEN","ho":false,"co":false},
{"id":"sentry-user-token","re":"\\b(sntryu_[a-f0-9]{64})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["sntryu_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"settlemint-application-access-token","re":"\\b(sm_aat_[a-zA-Z0-9]{16})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["sm_aat"],"lb":"TOKEN","ho":false,"co":false},
{"id":"settlemint-personal-access-token","re":"\\b(sm_pat_[a-zA-Z0-9]{16})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["sm_pat"],"lb":"TOKEN","ho":false,"co":false},
{"id":"settlemint-service-access-token","re":"\\b(sm_sat_[a-zA-Z0-9]{16})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["sm_sat"],"lb":"TOKEN","ho":false,"co":false},
{"id":"shippo-api-token","re":"\\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["shippo_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"shopify-access-token","re":"shpat_[a-fA-F0-9]{32}","fl":"","kw":["shpat_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"shopify-custom-access-token","re":"shpca_[a-fA-F0-9]{32}","fl":"","kw":["shpca_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"shopify-private-app-access-token","re":"shppa_[a-fA-F0-9]{32}","fl":"","kw":["shppa_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"shopify-shared-secret","re":"shpss_[a-fA-F0-9]{32}","fl":"","kw":["shpss_"],"lb":"SECRET","ho":false,"co":false},
{"id":"sidekiq-secret","re":"[\\w.-]{0,50}?(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-f0-9]{8}:[a-f0-9]{8})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["bundle_enterprise__contribsys__com","bundle_gems__contribsys__com"],"lb":"SECRET","ho":false,"co":false},
{"id":"sidekiq-sensitive-url","re":"\\bhttps?://([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\\/|\\#|\\?|:]|$)","fl":"i","kw":["gems.contribsys.com","enterprise.contribsys.com"],"lb":"KEY","ho":false,"co":false},
{"id":"slack-app-token","re":"xapp-\\d-[A-Z0-9]+-\\d+-[a-z0-9]+","fl":"i","kw":["xapp"],"lb":"TOKEN","ho":false,"co":false},
{"id":"slack-bot-token","re":"xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*","fl":"","kw":["xoxb"],"lb":"TOKEN","ho":false,"co":false},
{"id":"slack-config-access-token","re":"xoxe.xox[bp]-\\d-[A-Z0-9]{163,166}","fl":"i","kw":["xoxe.xoxb-","xoxe.xoxp-"],"lb":"TOKEN","ho":false,"co":false},
{"id":"slack-config-refresh-token","re":"xoxe-\\d-[A-Z0-9]{146}","fl":"i","kw":["xoxe-"],"lb":"TOKEN","ho":false,"co":false},
{"id":"slack-legacy-bot-token","re":"xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}","fl":"","kw":["xoxb"],"lb":"TOKEN","ho":false,"co":false},
{"id":"slack-legacy-token","re":"xox[os]-\\d+-\\d+-\\d+-[a-fA-F\\d]+","fl":"","kw":["xoxo","xoxs"],"lb":"TOKEN","ho":false,"co":false},
{"id":"slack-legacy-workspace-token","re":"xox[ar]-(?:\\d-)?[0-9a-zA-Z]{8,48}","fl":"","kw":["xoxa","xoxr"],"lb":"TOKEN","ho":false,"co":false},
{"id":"slack-user-token","re":"xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}","fl":"","kw":["xoxp-","xoxe-"],"lb":"TOKEN","ho":false,"co":false},
{"id":"slack-webhook-url","re":"(?:https?://)?hooks.slack.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}","fl":"","kw":["hooks.slack.com"],"lb":"KEY","ho":false,"co":false},
{"id":"snyk-api-token","re":"[\\w.-]{0,50}?(?:snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["snyk"],"lb":"TOKEN","ho":false,"co":false},
{"id":"sonar-api-token","re":"[\\w.-]{0,50}?(?:sonar[_.-]?(login|token))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}((?:squ_|sqp_|sqa_)?[a-z0-9=_\\-]{40})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["sonar"],"lb":"TOKEN","ho":false,"co":false},
{"id":"sourcegraph-access-token","re":"\\b(\\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}|[a-fA-F0-9]{40})\\b)(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["sgp_","sourcegraph"],"lb":"TOKEN","ho":false,"co":false},
{"id":"square-access-token","re":"\\b((?:EAAA|sq0atp-)[\\w-]{22,60})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["sq0atp-","eaaa"],"lb":"TOKEN","ho":false,"co":false},
{"id":"squarespace-access-token","re":"[\\w.-]{0,50}?(?:squarespace)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["squarespace"],"lb":"TOKEN","ho":false,"co":false},
{"id":"stripe-access-token","re":"\\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["sk_test","sk_live","sk_prod","rk_test","rk_live","rk_prod"],"lb":"TOKEN","ho":false,"co":false},
{"id":"travisci-access-token","re":"[\\w.-]{0,50}?(?:travis)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{22})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["travis"],"lb":"TOKEN","ho":false,"co":false},
{"id":"twilio-api-key","re":"SK[0-9a-fA-F]{32}","fl":"","kw":["sk"],"lb":"KEY","ho":false,"co":false},
{"id":"twitch-api-token","re":"[\\w.-]{0,50}?(?:twitch)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{30})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["twitch"],"lb":"TOKEN","ho":false,"co":false},
{"id":"twitter-access-secret","re":"[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{45})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["twitter"],"lb":"SECRET","ho":false,"co":false},
{"id":"twitter-access-token","re":"[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([0-9]{15,25}-[a-zA-Z0-9]{20,40})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["twitter"],"lb":"TOKEN","ho":false,"co":false},
{"id":"twitter-api-key","re":"[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{25})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["twitter"],"lb":"KEY","ho":false,"co":false},
{"id":"twitter-api-secret","re":"[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{50})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["twitter"],"lb":"SECRET","ho":false,"co":false},
{"id":"twitter-bearer-token","re":"[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}(A{22}[a-zA-Z0-9%]{80,100})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["twitter"],"lb":"TOKEN","ho":false,"co":false},
{"id":"typeform-api-token","re":"[\\w.-]{0,50}?(?:typeform)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}(tfp_[a-z0-9\\-_\\.=]{59})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["tfp_"],"lb":"TOKEN","ho":false,"co":false},
{"id":"vault-batch-token","re":"\\b(hvb\\.[\\w-]{138,300})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"","kw":["hvb."],"lb":"TOKEN","ho":false,"co":false},
{"id":"vault-service-token","re":"\\b((?:hvs\\.[\\w-]{90,120}|s\\.(?:[a-z0-9]{24})))(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["hvs.","s."],"lb":"TOKEN","ho":true,"co":false},
{"id":"yandex-access-token","re":"[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}(t1\\.[A-Z0-9a-z_-]+[=]{0,2}\\.[A-Z0-9a-z_-]{86}[=]{0,2})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["yandex"],"lb":"TOKEN","ho":false,"co":false},
{"id":"yandex-api-key","re":"[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}(AQVN[A-Za-z0-9_\\-]{35,38})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["yandex"],"lb":"KEY","ho":false,"co":false},
{"id":"yandex-aws-access-token","re":"[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}(YC[a-zA-Z0-9_\\-]{38})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["yandex"],"lb":"TOKEN","ho":false,"co":false},
{"id":"zendesk-secret-key","re":"[\\w.-]{0,50}?(?:zendesk)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[`'\"\\s=]{0,5}([a-z0-9]{40})(?:[`'\"\\s;]|\\\\[nr]|$)","fl":"i","kw":["zendesk"],"lb":"SECRET","ho":false,"co":false}
];
  var RULEPACK_RE = null, RULEPACK_BYKW = null;
  function rulepackIndex(){
    if(RULEPACK_RE) return;
    var byKw = {}, all = [];
    for(var i=0;i<RULEPACK.length;i++){
      var r = RULEPACK[i];
      r._c = r._c || new RegExp(r.re, r.fl);
      for(var j=0;j<r.kw.length;j++){
        var k = r.kw[j];
        if(!byKw[k]){ byKw[k] = []; all.push(k); }
        byKw[k].push(r);
      }
    }
    all.sort(function(a,b){ return b.length - a.length; });
    var esc = all.map(function(k){ return k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); });
    RULEPACK_RE = new RegExp(esc.join("|"), "g");
    RULEPACK_BYKW = byKw;
  }
  var RULE_WINDOW = 2048;
  function rulepackMatch(line, low, allowed){
    rulepackIndex();
    RULEPACK_RE.lastIndex = 0;
    var m, tried = {}, hits = [];
    while((m = RULEPACK_RE.exec(low)) !== null){
      var k = m[0], at = m.index;
      var from = at - RULE_WINDOW; if(from < 0) from = 0;
      var to = at + k.length + RULE_WINDOW; if(to > line.length) to = line.length;
      var window = (from === 0 && to === line.length) ? line : line.slice(from, to);
      var rs = RULEPACK_BYKW[k];
      for(var i=0;i<rs.length;i++){
        var r = rs[i];
        var key = r.id + "@" + from;
        if(tried[key]) continue;
        tried[key] = 1;
        var sub = window, base = from, mm, val;
        for(;;){
          r._c.lastIndex = 0;
          mm = r._c.exec(sub);
          if(!mm) break;
          val = mm[1] !== undefined ? mm[1] : mm[0];
          if(allowed && allowed.length && allowed.indexOf(val) >= 0 && mm[0].length > 0){
            sub = sub.slice(mm.index + mm[0].length); base += mm.index + mm[0].length; continue;
          }
          break;
        }
        if(mm){
          if(PLACEHOLDER.test(val)) continue;
          hits.push({ tier:"T1", category:r.id, label:r.lb, value:val, hoisted:r.ho||undefined, at:base + mm.index });
        }
      }
      if(RULEPACK_RE.lastIndex === m.index) RULEPACK_RE.lastIndex++;
    }
    if(!hits.length) return null;
    hits.sort(function(a,b){ return a.at !== b.at ? a.at - b.at : (a.category < b.category ? -1 : a.category > b.category ? 1 : 0); });
    var best = hits[0];
    delete best.at;
    return best;
  }
  var KV_WINDOW = 2048;
  function kvMatchWindowed(line, low){
    if(!kvMayMatch(low)) return null;
    if(line.length <= KV_WINDOW * 2) return KV.exec(line);
    for(var t=0; t<KV_TRIGGERS.length; t++){
      var at = low.indexOf(KV_TRIGGERS[t]);
      while(at >= 0){
        var from = at - KV_WINDOW; if(from < 0) from = 0;
        var to = at + KV_WINDOW; if(to > line.length) to = line.length;
        var hit = KV.exec(line.slice(from, to));
        if(hit) return hit;
        at = low.indexOf(KV_TRIGGERS[t], at + 1);
      }
    }
    return null;
  }

  function classifyLine(line){
    line = asText(line);
    var i, m, low=line.toLowerCase();
    var tooLong = line.length > MAX_SCAN_LINE;
    var allowed = [];
    for(i=0;i<TIER1.length;i++){
      m=TIER1[i].re.exec(line);
      if(m){
        if(TIER1[i].name==="generic_40hex" && PLACEHOLDER.test(line)) continue;
        var off = 0;
        while(m && TIER1[i].allow && TIER1[i].allow.some(function(a){ return a.test(m[0]); })){
          allowed.push(m[0]); off += m.index + m[0].length; m = TIER1[i].re.exec(line.slice(off));
        }
        if(!m) continue;
        return {tier:"T1", category:TIER1[i].name, label:TIER1[i].label, value:m[0]};
      }
    }
    if(low.indexOf("@")>=0 && !tooLong){
      m=EMAIL.exec(line);
      if(m && validTld(m[2]) && !PLACEHOLDER.test(m[0])) return {tier:"T2", category:"email", label:"EMAIL", value:m[0]};
    }
    if(!tooLong){
      var rp = rulepackMatch(line, low, allowed);
      if(rp) return rp;
    }

    if(hasContext(low, SSN_CTX)){
      m=SSN.exec(line);
      if(m) return {tier:"T2", category:"ssn", label:"SSN", value:m[0]};
    }
    if(hasContext(low, CC_CTX)){
      m=CC.exec(line);
      if(m && luhn(m[0])) return {tier:"T2", category:"credit_card", label:"CARD", value:m[0]};
    }
    if(hasContext(low, IP_CTX) && !tooLong){
      m=IP.exec(line);
      if(m) return {tier:"T2", category:"ipv4", label:"IP", value:m[0]};
    }
    m = kvMatchWindowed(line, low);
    if(m){
      var val=m[1];
      if(PLACEHOLDER.test(val)) return null;
      var classes=(/[a-z]/.test(val)?1:0)+(/[A-Z]/.test(val)?1:0)+(/[0-9]/.test(val)?1:0);
      if(classes>=2 && val.length>=8 && entropy(val)>=3.0) return {tier:"T3", category:"kv_secret", label:"SECRET", value:val};
    }
    return null;
  }

  var MAX_PER_LINE = 10000;
  function classifyAll(line){
    var cur=asText(line), found=[], r, at, n=0, pad;
    while(n++ < MAX_PER_LINE && (r=classifyLine(cur))){
      at = r.value ? cur.indexOf(r.value) : -1;
      if(at < 0){ found.push({at:found.length ? found[found.length-1].at : 0, r:r}); break; }
      found.push({at:at, r:r});
      pad = new Array(r.value.length+1).join(" ");
      cur = cur.slice(0, at) + pad + cur.slice(at + r.value.length);
    }
    found.sort(function(a,b){ return a.at-b.at; });
    return found.map(function(f){ return f.r; });
  }

  function scan(text){
    var lines=asText(text).split(/\r?\n/), out=[], i, j, all;
    for(i=0;i<lines.length;i++){
      all=classifyAll(lines[i]);
      for(j=0;j<all.length;j++){ all[j].line=i+1; out.push(all[j]); }
    }
    return out;
  }
  function unscannedLines(text){
    var lines=asText(text).split(/\r?\n/), out=[], i;
    for(i=0;i<lines.length;i++){ if(lines[i].length > MAX_SCAN_LINE) out.push({line:i+1, length:lines[i].length}); }
    return out;
  }

  function compressLabel(label){
    var words=label.split("_").filter(function(w){return w.length>0;});
    function ac(w){ return w.length<=2 ? w : (w.charAt(0)+w.charAt(w.length-1)); }
    if(words.length===1) return ac(words[0]);
    var minLen=Math.min.apply(null, words.map(function(w){return w.length;})), kept=false;
    return words.map(function(w){ if(!kept && w.length===minLen){ kept=true; return w; } return ac(w); }).join("_");
  }
  function labelOfLiteral(v){ var r=classifyLine(v); return r ? r.label : "SECRET"; }
  function occurrences(hay,needle){ return needle ? hay.split(needle).length-1 : 0; }

  function removeDenylist(text, denylist){
    text = asText(text);
    var seen={}, items=[];
    asList(denylist).forEach(function(s){ if(s && s.length>0 && !seen[s]){ seen[s]=1; items.push(s); } });
    var withPos=items.map(function(v){ return {v:v, pos:text.indexOf(v)}; }).filter(function(o){ return o.pos>=0; });
    withPos.sort(function(a,b){ return a.pos!==b.pos ? a.pos-b.pos : b.v.length-a.v.length; });
    var counters={}, map=[], out=text;
    withPos.forEach(function(o){
      var comp=compressLabel(labelOfLiteral(o.v));
      counters[comp]=(counters[comp]||0)+1;
      var token="GEODE_"+comp+"_"+counters[comp];
      while(text.indexOf(token)>=0 || out.indexOf(token)>=0){ counters[comp]++; token="GEODE_"+comp+"_"+counters[comp]; }
      map.push({token:token, value:o.v, label:labelOfLiteral(o.v), count:0});
    });
    map.slice().sort(function(a,b){ return b.value.length-a.value.length; })
       .forEach(function(e){
         var parts=out.split(e.value);
         e.count = parts.length-1;
         out = parts.join(e.token);
       });
    map.forEach(function(e){
      if(e.count===0){
        if(out.indexOf(e.value)>=0){ e.leaked=true; }
        else {
          var by=null;
          map.forEach(function(o){ if(o!==e && o.count>0 && o.value.indexOf(e.value)>=0 && (!by || o.value.length<by.length)) by=o.value; });
          e.subsumedBy = by;
        }
      }
    });
    return {output:out, map:map};
  }

  var PLACEHOLDER_TOKEN=/^GEODE_[A-Z0-9]+(?:_[A-Z0-9]+)*_\d+$/;
  function detectCandidates(text, denylist){
    var dl={}; asList(denylist).forEach(function(s){ if(s) dl[s]=1; });
    return scan(text).filter(function(f){ return !dl[f.value] && !PLACEHOLDER_TOKEN.test(f.value); });
  }

  function unmap(text, map){
    var out=asText(text);
    asList(map).slice().sort(function(a,b){ return b.token.length-a.token.length; })
       .forEach(function(e){ out=out.split(e.token).join(e.value); });
    return out;
  }

  var K256=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  function utf8bytes(s){
    var b=[],i,c,c2,cp;
    for(i=0;i<s.length;i++){
      c=s.charCodeAt(i);
      if(c<0x80) b.push(c);
      else if(c<0x800) b.push(0xc0|(c>>6),0x80|(c&0x3f));
      else if(c>=0xd800&&c<0xdc00){ c2=s.charCodeAt(++i); cp=0x10000+((c&0x3ff)<<10)+(c2&0x3ff);
        b.push(0xf0|(cp>>18),0x80|((cp>>12)&0x3f),0x80|((cp>>6)&0x3f),0x80|(cp&0x3f)); }
      else b.push(0xe0|(c>>12),0x80|((c>>6)&0x3f),0x80|(c&0x3f));
    }
    return b;
  }
  function sha256hex(str){
    var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    var b=utf8bytes(str), l=b.length, i, t;
    b.push(0x80); while(b.length%64!==56) b.push(0);
    var bits=l*8, hi=Math.floor(bits/0x100000000), lo=bits>>>0;
    b.push((hi>>>24)&255,(hi>>>16)&255,(hi>>>8)&255,hi&255,(lo>>>24)&255,(lo>>>16)&255,(lo>>>8)&255,lo&255);
    function rotr(x,n){ return (x>>>n)|(x<<(32-n)); }
    for(i=0;i<b.length;i+=64){
      var w=new Array(64);
      for(t=0;t<16;t++) w[t]=((b[i+t*4]<<24)|(b[i+t*4+1]<<16)|(b[i+t*4+2]<<8)|(b[i+t*4+3]))|0;
      for(t=16;t<64;t++){
        var x15=w[t-15], x2=w[t-2];
        var s0=rotr(x15,7)^rotr(x15,18)^(x15>>>3);
        var s1=rotr(x2,17)^rotr(x2,19)^(x2>>>10);
        w[t]=(w[t-16]+s0+w[t-7]+s1)|0;
      }
      var a=H[0],bb=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
      for(t=0;t<64;t++){
        var S1=rotr(e,6)^rotr(e,11)^rotr(e,25), ch=(e&f)^((~e)&g);
        var t1=(h+S1+ch+K256[t]+w[t])|0;
        var S0=rotr(a,2)^rotr(a,13)^rotr(a,22), maj=(a&bb)^(a&c)^(bb&c);
        var t2=(S0+maj)|0;
        h=g;g=f;f=e;e=(d+t1)|0;d=c;c=bb;bb=a;a=(t1+t2)|0;
      }
      H[0]=(H[0]+a)|0;H[1]=(H[1]+bb)|0;H[2]=(H[2]+c)|0;H[3]=(H[3]+d)|0;
      H[4]=(H[4]+e)|0;H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+h)|0;
    }
    var out=""; for(i=0;i<8;i++) out+=("0000000"+(H[i]>>>0).toString(16)).slice(-8);
    return out;
  }

  function rulesetDescriptor(){
    var rules=[];
    TIER1.forEach(function(r){ rules.push({tier:1,name:r.name,label:r.label,source:r.re.source,flags:r.re.flags,allow:(r.allow||[]).map(function(a){return a.source;})}); });
    rules.push({tier:2,name:"email",source:EMAIL.source,flags:EMAIL.flags,tld:Object.keys(GTLD).sort()});
    rules.push({tier:2,name:"ssn",source:SSN.source,flags:SSN.flags,ctx:SSN_CTX.slice().sort()});
    rules.push({tier:2,name:"credit_card",source:CC.source,flags:CC.flags,ctx:CC_CTX.slice().sort(),luhn:true});
    rules.push({tier:2,name:"ipv4",source:IP.source,flags:IP.flags,ctx:IP_CTX.slice().sort()});
    rules.push({tier:3,name:"kv_secret",source:KV.source,flags:KV.flags,minClasses:2,minLen:8,minEntropy:3});
    return JSON.stringify({pack:RULESET.name,version:RULESET.version,snapshot:RULESET.snapshot_date,
      suppression:{source:PLACEHOLDER.source,flags:PLACEHOLDER.flags},rules:rules});
  }

  var COLLAPSE_VAR = /(GEODE_[A-Z0-9]+(?:_[A-Z0-9]+)*_\d+)|(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?)|(\d{2}:\d{2}:\d{2}(?:\.\d+)?)|([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})|((?:\d{1,3}\.){3}\d{1,3})|(0x[0-9a-fA-F]+|[0-9a-fA-F]{12,})|(\d+)/g;
  function tokenizeLine(line){
    line = asText(line);
    var slots=[];
    var template=line.replace(COLLAPSE_VAR, function(m,geode,ts,clk,uuid,ip,hex,num){
      if(geode) return m;
      var type = ts?"ts":clk?"clk":uuid?"uuid":ip?"ip":hex?"hex":"num";
      slots.push({type:type, value:m});
      return ""+type+"";
    });
    return {template:template, slots:slots};
  }
  function collapse(text, opts){
    opts=opts||{};
    var threshold=(opts.threshold!=null)?opts.threshold:0.15;
    text = asText(text);
    var lines=text.split(/\r?\n/), n=lines.length;
    var toks=lines.map(tokenizeLine);
    function keyOf(tk){
      var bits=[];
      tk.slots.forEach(function(s){ bits.push(s.type==="num" ? ("="+s.value) : "#"); });
      return tk.template+""+bits.join("");
    }
    var keys=toks.map(keyOf);
    var out=[], detail=[], removed=0, groupsCollapsed=0, kept=0, i=0;
    while(i<n){
      var j=i+1; while(j<n && keys[j]===keys[i]) j++;
      var K=j-i;
      out.push(lines[i]); kept++;
      if(K>1){
        removed+=(K-1); groupsCollapsed++;
        detail.push({rep:lines[i], removed:K-1});
        out.push("… ⟦GEODE collapsed "+(K-1)+" near-duplicate line"+((K-1)===1?"":"s")+"⟧");
      }
      i=j;
    }
    var output=out.join("\n");
    var y = n>0 ? removed/n : 0;
    return {
      output:output,
      meets_threshold:(y>=threshold && removed>0),
      detail:detail,
      accounting:{ input_lines:n, distinct_lines_kept:kept, groups_collapsed:groupsCollapsed,
        lines_removed:removed, annotations_added:groupsCollapsed,
        output_fraction: text.length ? +(output.length/text.length).toFixed(4) : 1, yield:+y.toFixed(4) }
    };
  }

  function buildReceipt(o){
    var input=o.input||"", output=o.output||"", denylist=o.denylist||[], map=o.map||[], collapse=o.collapse||null;
    var seen={}, declared=0;
    denylist.forEach(function(s){ if(s&&s.length>0&&!seen[s]){ seen[s]=1; declared++; } });
    var residual=0; Object.keys(seen).forEach(function(s){ if(output.indexOf(s)>=0) residual++; });
    var counts={}; map.forEach(function(e){ counts[e.label]=(counts[e.label]||0)+e.count; });
    var placeholders={}; Object.keys(counts).sort().forEach(function(k){ placeholders[k]=counts[k]; });
    var residualMatches=detectCandidates(output,[]).length;
    var receipt={
      receipt:"GeodeCode v1",
      tool:{ name:APP.name, version:APP.version, source_url:APP.source_url,
        verify:"to confirm which tool made this, sha256 the file you loaded and compare it to the digest published for this version" },
      ruleset:{ name:RULESET.name, version:RULESET.version, digest:"sha256:"+sha256hex(rulesetDescriptor()) },
      input:{ sha256:"sha256:"+sha256hex(input) },
      output:{ sha256:"sha256:"+sha256hex(output) },
      options:{ denylist_declared:declared, collapse: collapse?"on":"off", layer2:"surfaced_only" },
      layer1: collapse
        ? { denylist:{ declared:declared, removed_items:map.length, residual_after_rescan:residual, pass:residual===0 },
            collapse:{ distinct_lines_kept:collapse.distinct_lines_kept, groups_collapsed:collapse.groups_collapsed,
              lines_removed:collapse.lines_removed, annotations_added:collapse.annotations_added,
              output_fraction:collapse.output_fraction, yield:collapse.yield, pass:true } }
        : { denylist:{ declared:declared, removed_items:map.length, residual_after_rescan:residual, pass:residual===0 } },
      placeholders:placeholders,
      selfcheck:{ ruleset_scan_of_output:residualMatches,
        note: residualMatches===0
          ? "0 residual matches — anyone can re-scan this output with the published ruleset and confirm"
          : residualMatches+" residual candidate(s) the ruleset still flags; promote them to the deny-list and re-process to reach 0" },
      proves:"what was removed + which tool & ruleset did it — NOT when (no trusted time source)"
    };
    var skipped = unscannedLines(input);
    if(skipped.length){
      receipt.scan_limits = {
        lines_not_fully_scanned: skipped.length,
        max_scanned_line_length: MAX_SCAN_LINE,
        lines: skipped.slice(0,20),
        note: "these line(s) exceed the scan limit, so the deny-list still applied to them but the "
            + "pattern rules did not run on them — treat this receipt's residual count as covering "
            + "the remaining lines only"
      };
    }
    return { receipt:receipt, text:JSON.stringify(receipt,null,2) };
  }

  var API={ RULESET:RULESET, APP:APP, entropy:entropy, luhn:luhn, validTld:validTld, classifyLine:classifyLine,
    scan:scan, compressLabel:compressLabel, labelOfLiteral:labelOfLiteral, removeDenylist:removeDenylist,
    detectCandidates:detectCandidates, unmap:unmap, sha256hex:sha256hex, rulesetDescriptor:rulesetDescriptor,
    tokenizeLine:tokenizeLine, collapse:collapse, buildReceipt:buildReceipt,
    unscannedLines:unscannedLines, MAX_SCAN_LINE:MAX_SCAN_LINE };
  globalThis.GEODECODE_ENGINE = API;
  if(typeof module!=="undefined" && module.exports){ module.exports=API; }
})();

