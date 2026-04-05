#!/usr/bin/env node
'use strict';

/**
 * generate-bulk-definitions.js
 *
 * Generates 800+ ultra-compact sourcetype definitions for Cribl DataTap.
 * Each definition is ~800-1200 bytes of valid JSON.
 *
 * Usage: node scripts/generate-bulk-definitions.js
 */

const fs = require('fs');
const path = require('path');

const DEFINITIONS_DIR = path.join(__dirname, '..', 'src', 'definitions');
const INDEX_FILE = path.join(DEFINITIONS_DIR, 'index.js');

// ── Existing filenames (skip these) ─────────────────────────────────────────
const existingFiles = new Set(
  fs.readdirSync(DEFINITIONS_DIR).filter(f => f.endsWith('.json'))
);

// ── Common field templates ──────────────────────────────────────────────────
const F = {
  ts:       {name:'ts',type:'timestamp',config:{format:'iso8601',jitterMs:30000}},
  src_ip:   {name:'src_ip',type:'ip',config:{cidr:'10.0.0.0/8'}},
  dst_ip:   {name:'dst_ip',type:'ip',config:{cidr:'192.168.0.0/16'}},
  client_ip:{name:'client_ip',type:'ip',config:{cidr:'10.0.0.0/8'}},
  user:     {name:'user',type:'username',config:{pattern:'first.last'}},
  actor:    {name:'actor',type:'username',config:{pattern:'first.last'}},
  action:   {name:'action',type:'enum',config:{values:['allow','deny','drop','alert'],weights:[0.7,0.15,0.1,0.05]}},
  event:    {name:'event_type',type:'enum',config:{values:['login','logout','create','update','delete','read'],weights:[0.2,0.1,0.15,0.2,0.1,0.25]}},
  severity: {name:'severity',type:'enum',config:{values:['low','medium','high','critical'],weights:[0.4,0.3,0.2,0.1]}},
  status:   {name:'status',type:'enum',config:{values:['success','failure','error','pending'],weights:[0.7,0.15,0.1,0.05]}},
  result:   {name:'result',type:'enum',config:{values:['pass','fail','warn','info'],weights:[0.6,0.2,0.15,0.05]}},
  proto:    {name:'protocol',type:'enum',config:{values:['TCP','UDP','ICMP','HTTP','HTTPS','DNS'],weights:[0.3,0.2,0.05,0.2,0.2,0.05]}},
  port:     {name:'dst_port',type:'integer',config:{min:1,max:65535}},
  bytes:    {name:'bytes',type:'integer',config:{min:64,max:1048576}},
  duration: {name:'duration_ms',type:'integer',config:{min:1,max:30000}},
  id:       {name:'id',type:'uuid',config:{}},
  level:    {name:'level',type:'enum',config:{values:['info','warn','error','debug'],weights:[0.5,0.25,0.2,0.05]}},
  method:   {name:'method',type:'enum',config:{values:['GET','POST','PUT','DELETE','PATCH'],weights:[0.5,0.2,0.15,0.1,0.05]}},
  code:     {name:'status_code',type:'enum',config:{values:['200','301','403','404','500'],weights:[0.6,0.1,0.1,0.1,0.1]}},
  risk:     {name:'risk_score',type:'integer',config:{min:0,max:100}},
  threat:   {name:'threat_level',type:'enum',config:{values:['none','low','medium','high','critical'],weights:[0.3,0.25,0.2,0.15,0.1]}},
  category: {name:'category',type:'enum',config:{values:['authentication','authorization','network','system','application','data'],weights:[0.2,0.15,0.2,0.15,0.15,0.15]}},
  hostname: {name:'hostname',type:'enum',config:{values:['srv-web01','srv-db01','srv-app01','srv-fw01','srv-dc01','srv-mail01'],weights:[0.2,0.2,0.15,0.15,0.15,0.15]}},
  os:       {name:'os_type',type:'enum',config:{values:['Windows','Linux','macOS','iOS','Android'],weights:[0.35,0.3,0.15,0.1,0.1]}},
  region:   {name:'region',type:'enum',config:{values:['us-east-1','us-west-2','eu-west-1','ap-southeast-1'],weights:[0.35,0.3,0.2,0.15]}},
  cloud:    {name:'cloud_provider',type:'enum',config:{values:['aws','azure','gcp'],weights:[0.45,0.35,0.2]}},
  verdict:  {name:'verdict',type:'enum',config:{values:['clean','suspicious','malicious','unknown'],weights:[0.6,0.15,0.15,0.1]}},
  direction:{name:'direction',type:'enum',config:{values:['inbound','outbound','internal'],weights:[0.4,0.35,0.25]}},
  policy:   {name:'policy',type:'enum',config:{values:['default','strict','permissive','custom'],weights:[0.4,0.25,0.2,0.15]}},
  msg:      {name:'message',type:'enum',config:{values:['Request processed','Connection established','Access denied','Session expired','Config changed','Alert triggered'],weights:[0.3,0.2,0.15,0.15,0.1,0.1]}},
};

// ── JSON template builder ───────────────────────────────────────────────────
function buildJsonTemplate(fields) {
  const parts = fields.map(f => {
    if (f.type === 'integer' || f.type === 'counter') return `"${f.name}":{{${f.name}}}`;
    return `"${f.name}":"{{${f.name}}}"`;
  });
  return '{' + parts.join(',') + '}';
}

function buildSyslogTemplate(fields) {
  const kv = fields.filter(f => f.name !== 'ts').map(f => `${f.name}={{${f.name}}}`).join(' ');
  return `<{{priority}}>1 {{ts}} {{hostname}} {{app_name}} - - - ${kv}`;
}

function buildKVTemplate(fields) {
  return fields.map(f => `${f.name}={{${f.name}}}`).join(' ');
}

function buildCSVTemplate(fields) {
  return fields.map(f => `{{${f.name}}}`).join(',');
}

// ── Definition generator ────────────────────────────────────────────────────
function makeDef(sourcetype, vendor, product, format, description, fields, correlationHints, extraFields) {
  const allFields = [...fields];
  if (extraFields) allFields.push(...extraFields);

  let template;
  if (format === 'json') template = buildJsonTemplate(allFields);
  else if (format === 'syslog') template = buildSyslogTemplate(allFields);
  else if (format === 'csv') template = buildCSVTemplate(allFields);
  else if (format === 'kv') template = buildKVTemplate(allFields);
  else template = buildJsonTemplate(allFields);

  return {
    sourcetype,
    vendor,
    product,
    format: format === 'kv' ? 'text' : format,
    description,
    fields: allFields,
    template,
    correlationHints: correlationHints || { src_ip: 'src_ip', user: 'user' },
  };
}

// Helper to build field quickly
function ef(name, type, config) {
  return { name, type, config: config || {} };
}
function enumF(name, values, weights) {
  return { name, type: 'enum', config: { values, weights: weights || values.map(() => +(1/values.length).toFixed(2)) } };
}
function intF(name, min, max) {
  return { name, type: 'integer', config: { min, max } };
}

// ──────────────────────────────────────────────────────────────────────────────
// MASSIVE SOURCETYPE LIST — organized by category
// Each entry: [filename, sourcetype, vendor, product, format, description, fields[], correlationHints, extraFields[]]
// ──────────────────────────────────────────────────────────────────────────────

const BULK = [];

function add(filename, sourcetype, vendor, product, fmt, desc, fields, hints, extra) {
  BULK.push({ filename, sourcetype, vendor, product, format: fmt, description: desc, fields, hints, extra });
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY VENDORS — Firewalls
// ═══════════════════════════════════════════════════════════════════════════════
add('hillstone-fw','hillstone:fw','Hillstone','StoneOS','syslog','Hillstone firewall traffic log',
  [F.ts,F.src_ip,F.dst_ip,F.proto,F.port,F.action,F.bytes,F.severity],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('zone',['trust','untrust','dmz','mgmt'],[0.3,0.3,0.25,0.15])]);

add('huawei-fw','huawei:fw','Huawei','USG Firewall','syslog','Huawei USG firewall event log',
  [F.ts,F.src_ip,F.dst_ip,F.proto,F.port,F.action,F.bytes],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('policy_name',['default','internet','vpn','dmz'],[0.3,0.3,0.2,0.2])]);

add('sangfor-fw','sangfor:fw','Sangfor','NGAF','json','Sangfor NGAF firewall log',
  [F.ts,F.src_ip,F.dst_ip,F.action,F.proto,F.port,F.bytes,F.severity],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('app_category',['web','streaming','social','gaming','business'],[0.3,0.2,0.2,0.15,0.15])]);

add('stormshield-fw','stormshield:fw','Stormshield','SNS','syslog','Stormshield SNS firewall log',
  [F.ts,F.src_ip,F.dst_ip,F.action,F.proto,F.port,F.bytes],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('fw_rule',['rule_1','rule_2','rule_3','default'],[0.3,0.3,0.25,0.15])]);

add('clavister-fw','clavister:fw','Clavister','NetWall','syslog','Clavister NetWall firewall log',
  [F.ts,F.src_ip,F.dst_ip,F.action,F.proto,F.port,F.severity],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('interface',['wan0','lan0','dmz0','vpn0'],[0.3,0.3,0.2,0.2])]);

add('untangle-fw','untangle:fw','Untangle','NG Firewall','json','Untangle NG Firewall event log',
  [F.ts,F.src_ip,F.dst_ip,F.action,F.proto,F.port,F.bytes],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('app_name',['firewall','web-filter','virus-blocker','intrusion-prevention'],[0.3,0.25,0.25,0.2])]);

add('kerio-fw','kerio:fw','Kerio','Control','syslog','Kerio Control firewall log',
  [F.ts,F.src_ip,F.dst_ip,F.action,F.proto,F.port,F.bytes],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('rule_name',['allow_all','block_external','nat_rule','vpn_rule'],[0.3,0.3,0.2,0.2])]);

add('gajshield-fw','gajshield:fw','GajShield','GS Series','syslog','GajShield firewall traffic log',
  [F.ts,F.src_ip,F.dst_ip,F.action,F.proto,F.port,F.bytes],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('context',['data','application','identity','network'],[0.25,0.25,0.25,0.25])]);

add('usergate-fw','usergate:fw','UserGate','UTM','json','UserGate UTM firewall log',
  [F.ts,F.src_ip,F.dst_ip,F.action,F.proto,F.port,F.bytes,F.severity],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('rule_type',['firewall','nat','content_filter','app_control'],[0.35,0.25,0.2,0.2])]);

add('endian-fw','endian:fw','Endian','UTM','syslog','Endian UTM firewall log',
  [F.ts,F.src_ip,F.dst_ip,F.action,F.proto,F.port,F.bytes],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('service',['http','https','smtp','dns','ssh'],[0.25,0.25,0.2,0.15,0.15])]);

add('ipfire-fw','ipfire:fw','IPFire','IPFire','syslog','IPFire firewall log',
  [F.ts,F.src_ip,F.dst_ip,F.action,F.proto,F.port,F.bytes],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('chain',['INPUT','OUTPUT','FORWARD','CUSTOM'],[0.3,0.25,0.3,0.15])]);

add('smoothwall-fw','smoothwall:fw','Smoothwall','Express','syslog','Smoothwall firewall log',
  [F.ts,F.src_ip,F.dst_ip,F.action,F.proto,F.port],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('filter',['web','application','network','email'],[0.3,0.25,0.25,0.2])]);

add('clearos-fw','clearos:fw','ClearOS','ClearOS','syslog','ClearOS firewall log',
  [F.ts,F.src_ip,F.dst_ip,F.action,F.proto,F.port,F.bytes],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('group',['LAN','WAN','DMZ','VPN'],[0.3,0.3,0.2,0.2])]);

add('zentyal-fw','zentyal:fw','Zentyal','Server','syslog','Zentyal firewall log',
  [F.ts,F.src_ip,F.dst_ip,F.action,F.proto,F.port],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('module',['firewall','ids','vpn','proxy'],[0.35,0.25,0.2,0.2])]);

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY — IDS/IPS
// ═══════════════════════════════════════════════════════════════════════════════
add('tippingpoint-ips','tippingpoint:ips','TippingPoint','TPS','syslog','TippingPoint IPS alert log',
  [F.ts,F.src_ip,F.dst_ip,F.severity,F.action,F.proto],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('signature',['exploit','malware','recon','policy','anomaly'],[0.25,0.2,0.2,0.2,0.15]),intF('sig_id',1000,99999)]);

add('mcafee-ips','mcafee:ips','McAfee','Network Security','syslog','McAfee IPS event log',
  [F.ts,F.src_ip,F.dst_ip,F.severity,F.action],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('attack_type',['exploit','dos','reconnaissance','brute_force','malware'],[0.25,0.2,0.2,0.2,0.15]),intF('attack_id',100,9999)]);

add('cisco-ips','cisco:ips','Cisco','IPS','syslog','Cisco IPS alert log',
  [F.ts,F.src_ip,F.dst_ip,F.severity,F.action,F.proto],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('sig_category',['network','application','protocol','anomaly'],[0.3,0.25,0.25,0.2]),intF('sig_id',1000,50000)]);

add('hillstone-ips','hillstone:ips','Hillstone','IPS','syslog','Hillstone IPS alert log',
  [F.ts,F.src_ip,F.dst_ip,F.severity,F.action],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('threat_type',['exploit','malware','scan','ddos','anomaly'],[0.25,0.2,0.2,0.2,0.15])]);

add('ossec-hids','ossec:alert','OSSEC','HIDS','json','OSSEC HIDS alert log',
  [F.ts,F.src_ip,F.hostname,F.severity,F.user],
  {src_ip:'src_ip',user:'user'},
  [intF('rule_id',1,9999),enumF('rule_group',['syslog','authentication','firewall','ids','rootcheck'],[0.25,0.2,0.2,0.2,0.15])]);

add('samhain-hids','samhain:alert','Samhain','HIDS','json','Samhain HIDS integrity alert',
  [F.ts,F.hostname,F.severity,F.user],
  {user:'user'},
  [enumF('check_type',['file_integrity','login','logout','policy','kernel'],[0.3,0.2,0.15,0.2,0.15]),ef('file_path','enum',{values:['/etc/passwd','/etc/shadow','/bin/ls','/usr/sbin/sshd'],weights:[0.3,0.3,0.2,0.2]})]);

add('aide-hids','aide:alert','AIDE','AIDE','json','AIDE file integrity alert',
  [F.ts,F.hostname,F.severity],
  {},
  [enumF('change_type',['added','removed','changed','permissions'],[0.2,0.15,0.4,0.25]),ef('file_path','enum',{values:['/etc/hosts','/etc/resolv.conf','/var/log/auth.log','/etc/crontab'],weights:[0.25,0.25,0.25,0.25]})]);

add('tripwire-alert','tripwire:alert','Tripwire','Enterprise','json','Tripwire change detection alert',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('change_type',['file_modified','file_added','file_removed','permission_changed','attribute_changed'],[0.3,0.2,0.15,0.2,0.15]),ef('node_name','enum',{values:['web-srv','db-srv','app-srv','dc-srv'],weights:[0.3,0.25,0.25,0.2]})]);

add('falco-alert','falco:alert','Sysdig','Falco','json','Falco runtime security alert',
  [F.ts,F.severity,F.hostname,F.user],
  {user:'user'},
  [enumF('rule',['shell_in_container','write_sensitive_file','outbound_conn','privilege_escalation','unexpected_process'],[0.2,0.2,0.2,0.2,0.2]),enumF('output_type',['stdout','file','syslog','http'],[0.3,0.3,0.2,0.2])]);

add('sagan-alert','sagan:alert','Sagan','Sagan','json','Sagan log analysis alert',
  [F.ts,F.src_ip,F.severity,F.hostname],
  {src_ip:'src_ip'},
  [intF('rule_id',1,5000),enumF('classification',['attempted-recon','attempted-admin','policy-violation','suspicious-login'],[0.25,0.25,0.25,0.25])]);

add('securityonion-alert','securityonion:alert','Security Onion','SO','json','Security Onion alert log',
  [F.ts,F.src_ip,F.dst_ip,F.severity,F.proto],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('sensor',['snort','suricata','zeek','strelka'],[0.25,0.25,0.3,0.2]),enumF('alert_type',['intrusion','malware','anomaly','policy'],[0.3,0.25,0.25,0.2])]);

add('bro-ids','bro:notice','Bro','IDS','json','Bro IDS notice log',
  [F.ts,F.src_ip,F.dst_ip,F.proto,F.port],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('notice_type',['Scan::Port_Scan','SSL::Invalid_Server_Cert','HTTP::SQL_Injection','DNS::Tunneling'],[0.3,0.25,0.25,0.2])]);

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY — EDR/AV
// ═══════════════════════════════════════════════════════════════════════════════
add('cortex-xdr','cortex:xdr','Palo Alto','Cortex XDR','json','Cortex XDR alert log',
  [F.ts,F.src_ip,F.hostname,F.user,F.severity],
  {src_ip:'src_ip',user:'user'},
  [enumF('alert_type',['malware','exploit','behavioral','fileless','ransomware'],[0.25,0.2,0.2,0.2,0.15]),enumF('action_taken',['blocked','quarantined','reported','allowed'],[0.4,0.25,0.2,0.15])]);

add('kaspersky-ep','kaspersky:endpoint','Kaspersky','Endpoint Security','json','Kaspersky endpoint detection log',
  [F.ts,F.hostname,F.user,F.severity,F.status],
  {user:'user'},
  [enumF('detection_type',['virus','trojan','worm','ransomware','adware','pua'],[0.2,0.2,0.15,0.15,0.15,0.15]),enumF('object_type',['file','process','registry','url'],[0.35,0.25,0.2,0.2])]);

add('bitdefender-ep','bitdefender:endpoint','Bitdefender','GravityZone','json','Bitdefender GravityZone endpoint log',
  [F.ts,F.hostname,F.user,F.severity,F.status],
  {user:'user'},
  [enumF('module',['antimalware','firewall','content_control','device_control','aph'],[0.25,0.2,0.2,0.2,0.15]),enumF('threat_name',['Gen:Variant.Tedy','Trojan.GenericKD','Adware.Agent','Exploit.CVE'],[0.3,0.25,0.25,0.2])]);

add('avast-ep','avast:endpoint','Avast','Business Antivirus','json','Avast business endpoint log',
  [F.ts,F.hostname,F.user,F.status,F.severity],
  {user:'user'},
  [enumF('scan_type',['real_time','scheduled','manual','boot_time'],[0.4,0.3,0.2,0.1]),F.verdict]);

add('fsecure-ep','fsecure:endpoint','F-Secure','Elements','json','F-Secure Elements endpoint log',
  [F.ts,F.hostname,F.user,F.severity,F.status],
  {user:'user'},
  [enumF('detection_name',['Trojan.TR/Agent','Exploit.EXP/CVE','Malware.ML/PE','Riskware.RW/Tool'],[0.3,0.25,0.25,0.2]),enumF('response',['blocked','cleaned','quarantined','reported'],[0.35,0.25,0.25,0.15])]);

add('webroot-ep','webroot:endpoint','Webroot','Business Endpoint','json','Webroot endpoint protection log',
  [F.ts,F.hostname,F.user,F.status],
  {user:'user'},
  [enumF('threat_status',['active','cleaned','quarantined','allowed'],[0.2,0.3,0.3,0.2]),F.risk]);

add('comodo-ep','comodo:endpoint','Comodo','Advanced Endpoint','json','Comodo endpoint protection log',
  [F.ts,F.hostname,F.user,F.severity,F.status],
  {user:'user'},
  [enumF('containment',['contained','auto_contained','excluded','monitoring'],[0.3,0.25,0.25,0.2]),F.verdict]);

add('harfanglab-edr','harfanglab:edr','HarfangLab','EDR','json','HarfangLab EDR alert log',
  [F.ts,F.hostname,F.user,F.severity,F.status],
  {user:'user'},
  [enumF('rule_type',['sigma','yara','ioc','behavioral'],[0.3,0.25,0.25,0.2]),F.id]);

add('limacharlie-edr','limacharlie:edr','LimaCharlie','EDR','json','LimaCharlie EDR detection log',
  [F.ts,F.hostname,F.user,F.severity],
  {user:'user'},
  [enumF('detect_type',['process','network','file','registry','dns'],[0.25,0.2,0.2,0.2,0.15]),F.id]);

add('velociraptor-edr','velociraptor:hunt','Velociraptor','EDR','json','Velociraptor hunt result log',
  [F.ts,F.hostname,F.user,F.status],
  {user:'user'},
  [enumF('artifact',['Windows.System.Pslist','Linux.Sys.Users','Generic.Client.Info','Windows.EventLogs.EVTX'],[0.25,0.25,0.25,0.25]),F.id]);

add('osquery-result','osquery:result','osquery','osquery','json','osquery scheduled query result',
  [F.ts,F.hostname],
  {},
  [enumF('query_name',['process_events','socket_events','file_events','user_events','hardware_info'],[0.25,0.2,0.2,0.2,0.15]),enumF('action',['added','removed','snapshot'],[0.4,0.3,0.3])]);

add('gravityzone-ep','gravityzone:event','Bitdefender','GravityZone Cloud','json','GravityZone cloud console event',
  [F.ts,F.hostname,F.user,F.severity,F.status],
  {user:'user'},
  [enumF('module',['avc','hd','fw','cl','el'],[0.25,0.2,0.2,0.2,0.15]),F.id]);

add('xcitium-ep','xcitium:endpoint','Xcitium','Advanced Endpoint','json','Xcitium endpoint detection log',
  [F.ts,F.hostname,F.user,F.severity,F.verdict],
  {user:'user'},
  [enumF('file_verdict',['trusted','unknown','malicious','suspicious'],[0.4,0.25,0.2,0.15])]);

add('huntress-edr','huntress:detection','Huntress','Managed EDR','json','Huntress managed EDR detection',
  [F.ts,F.hostname,F.user,F.severity],
  {user:'user'},
  [enumF('finding_type',['persistent_foothold','ransomware_canary','suspicious_process','malicious_file'],[0.3,0.2,0.25,0.25]),F.status]);

add('threatlocker-ep','threatlocker:event','ThreatLocker','Ringfencing','json','ThreatLocker application control event',
  [F.ts,F.hostname,F.user,F.action,F.status],
  {user:'user'},
  [enumF('policy_type',['application','ringfencing','elevation','storage'],[0.3,0.25,0.25,0.2]),ef('app_name','enum',{values:['chrome.exe','powershell.exe','cmd.exe','python.exe','notepad.exe'],weights:[0.25,0.2,0.2,0.2,0.15]})]);

add('morphisec-ep','morphisec:event','Morphisec','Guard','json','Morphisec moving target defense event',
  [F.ts,F.hostname,F.user,F.severity],
  {user:'user'},
  [enumF('event_type',['prevention','detection','memory_protection','script_protection'],[0.3,0.25,0.25,0.2]),F.status]);

add('deepinstinct-ep','deepinstinct:event','Deep Instinct','Prevention Platform','json','Deep Instinct prevention event',
  [F.ts,F.hostname,F.user,F.severity,F.verdict],
  {user:'user'},
  [enumF('file_type',['exe','dll','script','document','archive'],[0.25,0.2,0.2,0.2,0.15]),F.status]);

add('halcyon-ep','halcyon:event','Halcyon','Anti-Ransomware','json','Halcyon anti-ransomware event',
  [F.ts,F.hostname,F.user,F.severity],
  {user:'user'},
  [enumF('event_class',['ransomware_blocked','encryption_detected','data_exfiltration','lateral_movement'],[0.3,0.25,0.25,0.2]),F.status]);

add('trellix-edr','trellix:edr','Trellix','EDR','json','Trellix EDR detection event',
  [F.ts,F.hostname,F.user,F.severity,F.status],
  {user:'user'},
  [enumF('detection_source',['edr','atp','ips','fw'],[0.35,0.25,0.2,0.2]),F.threat]);

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY — Email Security
// ═══════════════════════════════════════════════════════════════════════════════
add('abnormal-email','abnormal:email','Abnormal Security','Abnormal','json','Abnormal Security email threat detection',
  [F.ts,F.user,F.severity,F.status],
  {user:'user'},
  [enumF('threat_type',['phishing','bec','spam','malware','account_takeover'],[0.25,0.2,0.2,0.2,0.15]),enumF('action_taken',['blocked','quarantined','delivered','remediated'],[0.35,0.25,0.2,0.2])]);

add('agari-email','agari:event','Agari','Email Security','json','Agari email authentication event',
  [F.ts,F.user,F.status,F.src_ip],
  {src_ip:'src_ip',user:'user'},
  [enumF('auth_result',['pass','fail','softfail','none'],[0.5,0.2,0.2,0.1]),enumF('protocol',['dmarc','spf','dkim'],[0.35,0.35,0.3])]);

add('area1-email','area1:phishing','Area 1','Email Security','json','Area 1 phishing detection event',
  [F.ts,F.user,F.severity,F.verdict],
  {user:'user'},
  [enumF('disposition',['malicious','suspicious','spoof','spam','clean'],[0.2,0.2,0.15,0.2,0.25]),F.status]);

add('cofense-email','cofense:triage','Cofense','Triage','json','Cofense phishing triage event',
  [F.ts,F.user,F.severity,F.status],
  {user:'user'},
  [enumF('category',['credential_phishing','malware_delivery','bec','spam','benign'],[0.25,0.2,0.2,0.2,0.15]),F.id]);

add('ironscales-email','ironscales:event','IRONSCALES','Email Security','json','IRONSCALES email protection event',
  [F.ts,F.user,F.severity,F.status],
  {user:'user'},
  [enumF('classification',['phishing','spear_phishing','bec','spam','safe'],[0.2,0.2,0.15,0.2,0.25]),enumF('action',['removed','quarantined','warned','allowed'],[0.3,0.25,0.25,0.2])]);

add('tessian-email','tessian:event','Tessian','Email Security','json','Tessian email protection event',
  [F.ts,F.user,F.severity,F.status],
  {user:'user'},
  [enumF('event_type',['inbound_threat','outbound_dlp','misdirected_email','account_takeover'],[0.3,0.25,0.25,0.2])]);

add('vade-email','vade:email','Vade','Email Security','json','Vade email filtering event',
  [F.ts,F.user,F.verdict,F.status],
  {user:'user'},
  [enumF('filter_type',['phishing','malware','spam','scam','clean'],[0.2,0.2,0.2,0.15,0.25])]);

add('hornetsecurity-email','hornetsecurity:event','Hornetsecurity','Email Security','json','Hornetsecurity email protection event',
  [F.ts,F.user,F.status,F.severity],
  {user:'user'},
  [enumF('threat_category',['spam','phishing','malware','advanced_threat','clean'],[0.25,0.2,0.15,0.15,0.25])]);

add('spamtitan-email','spamtitan:event','SpamTitan','Gateway','json','SpamTitan email gateway event',
  [F.ts,F.src_ip,F.user,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('classification',['spam','ham','phishing','virus','quarantined'],[0.25,0.3,0.15,0.1,0.2])]);

add('libraesva-email','libraesva:event','Libraesva','ESG','json','Libraesva email security gateway event',
  [F.ts,F.user,F.status,F.severity],
  {user:'user'},
  [enumF('verdict',['clean','spam','phishing','malware','rejected'],[0.3,0.2,0.2,0.15,0.15])]);

add('trustifi-email','trustifi:event','Trustifi','Email Security','json','Trustifi email protection event',
  [F.ts,F.user,F.status,F.severity],
  {user:'user'},
  [enumF('protection_type',['encryption','dlp','threat_protection','archiving'],[0.3,0.25,0.25,0.2])]);

add('avanan-email','avanan:event','Avanan','Cloud Email Security','json','Avanan cloud email security event',
  [F.ts,F.user,F.severity,F.verdict],
  {user:'user'},
  [enumF('scan_result',['clean','phishing','malware','dlp_violation','suspicious'],[0.35,0.2,0.15,0.15,0.15])]);

add('material-email','material:event','Material Security','Email Security','json','Material Security email protection event',
  [F.ts,F.user,F.status,F.severity],
  {user:'user'},
  [enumF('action',['redacted','protected','alerted','released'],[0.3,0.3,0.2,0.2])]);

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY — CASB/SSE
// ═══════════════════════════════════════════════════════════════════════════════
add('lookout-casb','lookout:casb','Lookout','CASB','json','Lookout CASB event log',
  [F.ts,F.user,F.src_ip,F.severity,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('threat_type',['data_leak','malware','anomaly','policy_violation'],[0.25,0.25,0.25,0.25])]);

add('forcepoint-casb','forcepoint:casb','Forcepoint','ONE','json','Forcepoint ONE CASB event',
  [F.ts,F.user,F.src_ip,F.action,F.severity],
  {src_ip:'src_ip',user:'user'},
  [enumF('app',['office365','salesforce','box','slack','aws_console'],[0.25,0.2,0.2,0.2,0.15])]);

add('skyhigh-casb','skyhigh:casb','Skyhigh','Security Cloud','json','Skyhigh Security cloud event',
  [F.ts,F.user,F.src_ip,F.action,F.severity],
  {src_ip:'src_ip',user:'user'},
  [enumF('service',['shadow_it','dlp','threat_protection','compliance'],[0.25,0.25,0.25,0.25])]);

add('iboss-proxy','iboss:proxy','iBoss','Cloud Platform','json','iBoss cloud proxy event',
  [F.ts,F.src_ip,F.user,F.action,F.bytes],
  {src_ip:'src_ip',user:'user'},
  [enumF('category',['business','social_media','streaming','malware','phishing'],[0.3,0.2,0.2,0.15,0.15])]);

add('menlo-security','menlo:event','Menlo Security','Isolation','json','Menlo Security web isolation event',
  [F.ts,F.src_ip,F.user,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('isolation_type',['browser','document','email_link','api'],[0.35,0.25,0.25,0.15])]);

add('axis-security','axis:event','Axis Security','Atmos','json','Axis Security ZTNA event',
  [F.ts,F.src_ip,F.user,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('app_type',['web','ssh','rdp','tcp','udp'],[0.3,0.2,0.2,0.15,0.15])]);

add('cloudflare-access','cloudflare:access','Cloudflare','Access','json','Cloudflare Access ZTNA event',
  [F.ts,F.src_ip,F.user,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('decision',['allow','deny','non_identity','bypass'],[0.5,0.2,0.15,0.15])]);

add('zscaler-zpa','zscaler:zpa','Zscaler','ZPA','json','Zscaler ZPA private access log',
  [F.ts,F.src_ip,F.user,F.action,F.status,F.duration],
  {src_ip:'src_ip',user:'user'},
  [enumF('connector',['connector-east','connector-west','connector-eu','connector-apac'],[0.3,0.25,0.25,0.2])]);

add('netskope-ztna','netskope:ztna','Netskope','Private Access','json','Netskope ZTNA private access log',
  [F.ts,F.src_ip,F.user,F.action,F.status,F.duration],
  {src_ip:'src_ip',user:'user'},
  [enumF('publisher',['pub-dc01','pub-dc02','pub-cloud01'],[0.4,0.35,0.25])]);

add('cato-networks','cato:event','Cato Networks','SASE','json','Cato Networks SASE event log',
  [F.ts,F.src_ip,F.user,F.action,F.severity,F.bytes],
  {src_ip:'src_ip',user:'user'},
  [enumF('service',['firewall','ips','anti_malware','casb','ztna'],[0.25,0.2,0.2,0.2,0.15])]);

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY — WAF
// ═══════════════════════════════════════════════════════════════════════════════
add('sucuri-waf','sucuri:waf','Sucuri','WAF','json','Sucuri WAF event log',
  [F.ts,F.client_ip,F.method,F.code,F.action],
  {src_ip:'client_ip'},
  [enumF('block_reason',['sql_injection','xss','rfi','brute_force','ddos','bot'],[0.2,0.2,0.15,0.15,0.15,0.15])]);

add('wallarm-waf','wallarm:event','Wallarm','WAAP','json','Wallarm WAAP event log',
  [F.ts,F.client_ip,F.method,F.code,F.action],
  {src_ip:'client_ip'},
  [enumF('attack_type',['sqli','xss','xxe','ssrf','rce','path_traversal'],[0.2,0.2,0.15,0.15,0.15,0.15])]);

add('signalsciences-waf','signalsciences:event','Signal Sciences','WAF','json','Signal Sciences WAF event',
  [F.ts,F.client_ip,F.method,F.code,F.action],
  {src_ip:'client_ip'},
  [enumF('tag',['SQLI','XSS','CMDEXE','TRAVERSAL','USERAGENT','BACKDOOR'],[0.2,0.2,0.15,0.15,0.15,0.15])]);

add('reblaze-waf','reblaze:event','Reblaze','WAF','json','Reblaze WAF event log',
  [F.ts,F.client_ip,F.method,F.code,F.action],
  {src_ip:'client_ip'},
  [enumF('challenge_type',['bot','human','rate_limit','geo_block'],[0.3,0.25,0.25,0.2])]);

add('radware-waf','radware:waf','Radware','AppWall','json','Radware AppWall WAF event',
  [F.ts,F.client_ip,F.method,F.code,F.action,F.severity],
  {src_ip:'client_ip'},
  [enumF('violation',['sql_injection','cross_site_scripting','parameter_tampering','cookie_poisoning'],[0.3,0.25,0.25,0.2])]);

add('prophaze-waf','prophaze:event','Prophaze','WAF','json','Prophaze WAF event log',
  [F.ts,F.client_ip,F.method,F.action],
  {src_ip:'client_ip'},
  [enumF('threat',['bot','api_abuse','ddos','injection','zero_day'],[0.25,0.2,0.2,0.2,0.15])]);

add('apptrana-waf','apptrana:event','AppTrana','WAF','json','AppTrana WAF event log',
  [F.ts,F.client_ip,F.method,F.code,F.action],
  {src_ip:'client_ip'},
  [enumF('risk_level',['no_risk','low','medium','high','critical'],[0.3,0.2,0.2,0.2,0.1])]);

add('threatx-waf','threatx:event','ThreatX','WAF','json','ThreatX WAF event log',
  [F.ts,F.client_ip,F.method,F.action,F.risk],
  {src_ip:'client_ip'},
  [enumF('entity_type',['ip','fingerprint','session'],[0.4,0.35,0.25])]);

add('stackpath-waf','stackpath:waf','StackPath','WAF','json','StackPath WAF event log',
  [F.ts,F.client_ip,F.method,F.code,F.action],
  {src_ip:'client_ip'},
  [enumF('rule_type',['managed','custom','rate_limit','geo'],[0.3,0.25,0.25,0.2])]);

add('edgio-waf','edgio:waf','Edgio','Security','json','Edgio WAF event log',
  [F.ts,F.client_ip,F.method,F.code,F.action],
  {src_ip:'client_ip'},
  [enumF('waf_profile',['production','staging','custom','emergency'],[0.4,0.25,0.2,0.15])]);

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY — PAM
// ═══════════════════════════════════════════════════════════════════════════════
add('delinea-pam','delinea:pam','Delinea','Secret Server','json','Delinea PAM audit event',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('secret_type',['password','ssh_key','certificate','api_key'],[0.35,0.25,0.2,0.2]),F.id]);

add('wallix-pam','wallix:audit','Wallix','Bastion','json','Wallix Bastion PAM audit log',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('target_type',['ssh','rdp','http','database'],[0.3,0.3,0.2,0.2]),F.duration]);

add('oneidentity-pam','oneidentity:pam','One Identity','Safeguard','json','One Identity Safeguard audit event',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('session_type',['ssh','rdp','telnet','database'],[0.3,0.3,0.15,0.25])]);

add('centrify-pam','centrify:audit','Centrify','Vault','json','Centrify vault audit event',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('resource_type',['system','database','secret','role'],[0.3,0.25,0.25,0.2])]);

add('manageengine-pam','manageengine:pam','ManageEngine','PAM360','json','ManageEngine PAM360 audit log',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('operation',['checkout','checkin','view_password','session_record','approval'],[0.25,0.2,0.2,0.2,0.15])]);

add('keeper-pam','keeper:audit','Keeper','PAM','json','Keeper PAM audit event',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('record_type',['login','password','file','totp'],[0.3,0.3,0.2,0.2])]);

add('devolutions-pam','devolutions:audit','Devolutions','Server','json','Devolutions Server audit event',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('entry_type',['credential','session','vault','role'],[0.3,0.25,0.25,0.2])]);

add('boundary-pam','boundary:event','HashiCorp','Boundary','json','HashiCorp Boundary access event',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('target_type',['tcp','ssh','http','database'],[0.25,0.3,0.2,0.25])]);

add('strongdm-pam','strongdm:audit','StrongDM','StrongDM','json','StrongDM access audit log',
  [F.ts,F.user,F.src_ip,F.action,F.status,F.duration],
  {src_ip:'src_ip',user:'user'},
  [enumF('resource_type',['server','database','cluster','website'],[0.3,0.3,0.2,0.2])]);

add('teleport-pam','teleport:audit','Teleport','Teleport','json','Teleport access audit event',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('protocol',['ssh','kubernetes','database','app','desktop'],[0.25,0.2,0.2,0.2,0.15])]);

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY — IAM/SSO
// ═══════════════════════════════════════════════════════════════════════════════
add('keycloak-auth','keycloak:event','Keycloak','IAM','json','Keycloak IAM event log',
  [F.ts,F.user,F.src_ip,F.event,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('realm',['master','app','external','internal'],[0.2,0.3,0.25,0.25])]);

add('gluu-auth','gluu:event','Gluu','Gluu Server','json','Gluu IAM event log',
  [F.ts,F.user,F.src_ip,F.event,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('auth_method',['password','u2f','otp','social','webauthn'],[0.3,0.2,0.2,0.15,0.15])]);

add('wso2-auth','wso2:event','WSO2','Identity Server','json','WSO2 Identity Server event log',
  [F.ts,F.user,F.src_ip,F.event,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('flow',['authentication','authorization','provisioning','token'],[0.3,0.25,0.2,0.25])]);

add('fusionauth-event','fusionauth:event','FusionAuth','FusionAuth','json','FusionAuth authentication event',
  [F.ts,F.user,F.src_ip,F.event,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('login_type',['password','passwordless','social','mfa'],[0.35,0.2,0.25,0.2])]);

add('descope-auth','descope:event','Descope','Auth','json','Descope auth event log',
  [F.ts,F.user,F.src_ip,F.event,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('method',['otp','magic_link','oauth','passkey'],[0.3,0.25,0.25,0.2])]);

add('stytch-auth','stytch:event','Stytch','Auth','json','Stytch authentication event',
  [F.ts,F.user,F.src_ip,F.event,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('auth_factor',['email_magic_link','sms_otp','whatsapp_otp','webauthn','totp'],[0.25,0.2,0.2,0.2,0.15])]);

add('workos-auth','workos:event','WorkOS','SSO','json','WorkOS SSO event log',
  [F.ts,F.user,F.src_ip,F.event,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('connection_type',['saml','oidc','magic_auth','password'],[0.35,0.25,0.2,0.2])]);

add('frontegg-auth','frontegg:event','Frontegg','Auth','json','Frontegg authentication event',
  [F.ts,F.user,F.src_ip,F.event,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('tenant_id',['tenant_a','tenant_b','tenant_c','tenant_d'],[0.3,0.25,0.25,0.2])]);

add('propelauth-event','propelauth:event','PropelAuth','Auth','json','PropelAuth authentication event',
  [F.ts,F.user,F.src_ip,F.event,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('org_role',['admin','member','viewer','owner'],[0.2,0.35,0.25,0.2])]);

add('clerk-auth','clerk:event','Clerk','Auth','json','Clerk authentication event',
  [F.ts,F.user,F.src_ip,F.event,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('strategy',['password','google_oauth','github_oauth','email_link','phone_code'],[0.25,0.2,0.2,0.2,0.15])]);

add('supabase-auth','supabase:auth','Supabase','Auth','json','Supabase authentication event',
  [F.ts,F.user,F.src_ip,F.event,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('provider',['email','google','github','apple','phone'],[0.3,0.2,0.2,0.15,0.15])]);

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY — NDR/NTA
// ═══════════════════════════════════════════════════════════════════════════════
add('darktrace-alert','darktrace:alert','Darktrace','Enterprise','json','Darktrace AI-detected anomaly alert',
  [F.ts,F.src_ip,F.dst_ip,F.severity,F.proto],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('model',['unusual_connection','data_exfiltration','credential_use','lateral_movement','c2_communication'],[0.2,0.2,0.2,0.2,0.2]),F.risk]);

add('vectra-alert','vectra:detection','Vectra','Cognito','json','Vectra AI detection alert',
  [F.ts,F.src_ip,F.dst_ip,F.severity],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('detection_type',['command_and_control','exfiltration','lateral_movement','reconnaissance','botnet'],[0.2,0.2,0.2,0.2,0.2]),intF('threat_score',0,100),intF('certainty_score',0,100)]);

add('extrahop-alert','extrahop:detection','ExtraHop','Reveal(x)','json','ExtraHop Reveal(x) detection event',
  [F.ts,F.src_ip,F.dst_ip,F.severity,F.proto],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('category',['lateral_movement','data_exfiltration','c2','privilege_escalation','ransomware'],[0.2,0.2,0.2,0.2,0.2]),F.risk]);

add('corelight-event','corelight:event','Corelight','Sensor','json','Corelight network evidence event',
  [F.ts,F.src_ip,F.dst_ip,F.proto,F.port,F.bytes],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('log_type',['conn','dns','http','ssl','files','notice'],[0.2,0.2,0.15,0.15,0.15,0.15])]);

add('gigamon-event','gigamon:event','Gigamon','ThreatInsight','json','Gigamon ThreatInsight detection event',
  [F.ts,F.src_ip,F.dst_ip,F.severity,F.proto],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('threat_type',['malware','cryptomining','c2','lateral_movement'],[0.3,0.2,0.25,0.25])]);

add('plixer-flow','plixer:flow','Plixer','Scrutinizer','json','Plixer Scrutinizer flow analytics event',
  [F.ts,F.src_ip,F.dst_ip,F.proto,F.port,F.bytes],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('alarm_type',['threshold','baseline','pattern','anomaly'],[0.3,0.25,0.25,0.2])]);

add('kentik-flow','kentik:flow','Kentik','Network Observability','json','Kentik flow analytics event',
  [F.ts,F.src_ip,F.dst_ip,F.proto,F.bytes],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('alert_policy',['ddos','capacity','performance','traffic_change'],[0.3,0.25,0.25,0.2]),F.region]);

add('stamus-ndr','stamus:alert','Stamus','Stamus NDR','json','Stamus NDR security event',
  [F.ts,F.src_ip,F.dst_ip,F.severity,F.proto],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('classification',['malware','exploit','policy','anomaly','recon'],[0.2,0.2,0.2,0.2,0.2])]);

add('ironnet-alert','ironnet:alert','IronNet','IronDefense','json','IronNet collective defense alert',
  [F.ts,F.src_ip,F.dst_ip,F.severity],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('category',['c2','data_loss','lateral_movement','insider_threat','ddos'],[0.2,0.2,0.2,0.2,0.2]),F.risk]);

add('bricata-alert','bricata:alert','Bricata','NDS','json','Bricata network detection alert',
  [F.ts,F.src_ip,F.dst_ip,F.severity,F.proto],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('detection_engine',['signature','anomaly','metadata','ml'],[0.3,0.25,0.25,0.2])]);

add('fidelis-alert','fidelis:alert','Fidelis','Network','json','Fidelis network detection alert',
  [F.ts,F.src_ip,F.dst_ip,F.severity,F.proto],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('alert_type',['malware','exfiltration','c2','policy','anomaly'],[0.2,0.2,0.2,0.2,0.2])]);

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY — Cloud Security
// ═══════════════════════════════════════════════════════════════════════════════
add('aqua-security','aqua:event','Aqua Security','Platform','json','Aqua Security container event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('control_type',['runtime','image_scan','network','compliance','drift'],[0.25,0.2,0.2,0.2,0.15]),F.user]);

add('sysdig-secure','sysdig:event','Sysdig','Secure','json','Sysdig Secure runtime event',
  [F.ts,F.hostname,F.severity,F.user],
  {user:'user'},
  [enumF('policy_type',['runtime','image_scanning','compliance','activity_audit'],[0.3,0.25,0.25,0.2])]);

add('snyk-vuln','snyk:finding','Snyk','Security','json','Snyk security finding',
  [F.ts,F.severity,F.status],
  {},
  [enumF('scan_type',['open_source','code','container','iac'],[0.3,0.25,0.25,0.2]),enumF('package_manager',['npm','pip','maven','go','nuget'],[0.3,0.2,0.2,0.15,0.15])]);

add('twistlock-event','twistlock:event','Palo Alto','Twistlock','json','Twistlock container security event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('rule_type',['vulnerability','compliance','runtime','network'],[0.3,0.25,0.25,0.2]),F.user]);

add('kubebench-result','kubebench:result','Aqua','kube-bench','json','kube-bench CIS benchmark result',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('section',['master','etcd','control_plane','worker','policies'],[0.2,0.15,0.2,0.25,0.2]),F.result]);

add('prowler-finding','prowler:finding','Prowler','Prowler','json','Prowler cloud security finding',
  [F.ts,F.severity,F.status,F.region],
  {},
  [enumF('service',['iam','s3','ec2','rds','lambda','cloudtrail'],[0.2,0.15,0.2,0.15,0.15,0.15]),F.cloud]);

add('scoutsuite-finding','scoutsuite:finding','NCC Group','ScoutSuite','json','ScoutSuite cloud audit finding',
  [F.ts,F.severity,F.cloud,F.region],
  {},
  [enumF('service',['iam','ec2','s3','rds','networking','logging'],[0.2,0.2,0.15,0.15,0.15,0.15]),F.status]);

add('cloudsploit-finding','cloudsploit:finding','Aqua','CloudSploit','json','CloudSploit cloud security finding',
  [F.ts,F.severity,F.cloud,F.region],
  {},
  [enumF('category',['iam','networking','storage','logging','encryption','monitoring'],[0.2,0.15,0.15,0.15,0.2,0.15]),F.status]);

add('dome9-event','dome9:event','Check Point','Dome9','json','CloudGuard Dome9 compliance event',
  [F.ts,F.severity,F.cloud,F.region,F.status],
  {},
  [enumF('rule_type',['network','iam','encryption','logging','monitoring'],[0.2,0.2,0.2,0.2,0.2])]);

add('ermetic-finding','ermetic:finding','Tenable','Ermetic','json','Ermetic cloud identity finding',
  [F.ts,F.severity,F.cloud,F.user],
  {user:'user'},
  [enumF('risk_type',['over_privileged','unused_permission','lateral_movement','data_access'],[0.3,0.25,0.25,0.2])]);

add('lightspin-finding','lightspin:finding','Lightspin','CNAPP','json','Lightspin cloud attack path finding',
  [F.ts,F.severity,F.cloud,F.region],
  {},
  [enumF('finding_type',['attack_path','vulnerability','misconfiguration','secret_exposure'],[0.25,0.25,0.25,0.25]),F.risk]);

add('cloudguard-event','cloudguard:event','Check Point','CloudGuard','json','CloudGuard workload protection event',
  [F.ts,F.severity,F.cloud,F.hostname,F.status],
  {},
  [enumF('protection_type',['runtime','image_assurance','admission_control','network'],[0.3,0.25,0.25,0.2])]);

add('trendcloud-event','trendcloud:event','Trend Micro','Cloud One','json','Trend Cloud One security event',
  [F.ts,F.severity,F.hostname,F.status,F.cloud],
  {},
  [enumF('module',['workload_security','container_security','file_storage','network_security','conformity'],[0.25,0.2,0.2,0.15,0.2])]);

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY — Vulnerability
// ═══════════════════════════════════════════════════════════════════════════════
add('invicti-scan','invicti:finding','Invicti','DAST','json','Invicti DAST scan finding',
  [F.ts,F.severity,F.status],
  {},
  [enumF('vulnerability',['sql_injection','xss','insecure_config','info_disclosure','csrf'],[0.2,0.2,0.2,0.2,0.2]),enumF('certainty',['confirmed','likely','possible'],[0.4,0.35,0.25])]);

add('acunetix-scan','acunetix:finding','Acunetix','DAST','json','Acunetix vulnerability scan finding',
  [F.ts,F.severity,F.status],
  {},
  [enumF('vuln_type',['injection','xss','config','disclosure','broken_auth'],[0.2,0.2,0.2,0.2,0.2]),F.risk]);

add('burpsuite-scan','burpsuite:finding','PortSwigger','Burp Suite','json','Burp Suite scan finding',
  [F.ts,F.severity],
  {},
  [enumF('issue_type',['injection','xss','ssrf','idor','authentication','crypto'],[0.2,0.15,0.15,0.15,0.2,0.15]),enumF('confidence',['certain','firm','tentative'],[0.4,0.35,0.25])]);

add('zap-scan','zap:finding','OWASP','ZAP','json','OWASP ZAP scan finding',
  [F.ts,F.severity,F.status],
  {},
  [enumF('alert',['sql_injection','xss','path_traversal','csrf','info_leak','missing_header'],[0.15,0.15,0.15,0.15,0.2,0.2]),intF('cwe_id',1,1000)]);

add('detectify-finding','detectify:finding','Detectify','Surface Monitoring','json','Detectify surface monitoring finding',
  [F.ts,F.severity,F.status],
  {},
  [enumF('asset_type',['domain','subdomain','ip','service'],[0.3,0.3,0.2,0.2]),F.risk]);

add('probely-finding','probely:finding','Probely','DAST','json','Probely DAST scan finding',
  [F.ts,F.severity,F.status],
  {},
  [enumF('owasp_category',['injection','broken_auth','sensitive_data','xxe','broken_access'],[0.2,0.2,0.2,0.2,0.2])]);

add('hostedscan-finding','hostedscan:finding','HostedScan','Security','json','HostedScan vulnerability finding',
  [F.ts,F.severity,F.status],
  {},
  [enumF('scanner',['nmap','openvas','sslyze','nikto'],[0.25,0.3,0.25,0.2]),F.risk]);

add('intruder-finding','intruder:finding','Intruder','VM','json','Intruder vulnerability finding',
  [F.ts,F.severity,F.status],
  {},
  [enumF('issue_type',['infrastructure','web','cloud','emerging'],[0.3,0.25,0.25,0.2]),F.risk]);

add('pentera-finding','pentera:finding','Pentera','BAS','json','Pentera breach simulation finding',
  [F.ts,F.severity,F.hostname],
  {},
  [enumF('technique',['credential_access','lateral_movement','privilege_escalation','defense_evasion','persistence'],[0.2,0.2,0.2,0.2,0.2]),F.risk]);

add('attackiq-result','attackiq:result','AttackIQ','BAS','json','AttackIQ breach simulation result',
  [F.ts,F.severity,F.status],
  {},
  [enumF('mitre_tactic',['initial_access','execution','persistence','privilege_escalation','defense_evasion','discovery'],[0.15,0.2,0.15,0.2,0.15,0.15]),F.result]);

add('safebreach-result','safebreach:result','SafeBreach','BAS','json','SafeBreach simulation result',
  [F.ts,F.severity,F.status],
  {},
  [enumF('attack_type',['network','endpoint','email','web','cloud'],[0.2,0.25,0.2,0.2,0.15]),F.result]);

add('cymulate-result','cymulate:result','Cymulate','BAS','json','Cymulate breach simulation result',
  [F.ts,F.severity,F.status],
  {},
  [enumF('vector',['email','web_gateway','waf','endpoint','data_exfiltration','lateral_movement'],[0.15,0.15,0.15,0.2,0.2,0.15]),F.risk]);

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY — SIEM/SOAR
// ═══════════════════════════════════════════════════════════════════════════════
add('sumologic-alert','sumologic:alert','Sumo Logic','CSE','json','Sumo Logic CSE alert',
  [F.ts,F.severity,F.user,F.src_ip,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('signal_type',['anomaly','threshold','chain','first_seen'],[0.25,0.3,0.25,0.2])]);

add('devo-alert','devo:alert','Devo','Platform','json','Devo platform alert',
  [F.ts,F.severity,F.src_ip,F.user],
  {src_ip:'src_ip',user:'user'},
  [enumF('alert_type',['correlation','anomaly','lookup','activeboards'],[0.3,0.25,0.25,0.2]),F.status]);

add('exabeam-alert','exabeam:alert','Exabeam','Fusion','json','Exabeam Fusion SIEM alert',
  [F.ts,F.severity,F.user,F.src_ip],
  {src_ip:'src_ip',user:'user'},
  [F.risk,enumF('model',['abnormal_logon','data_exfiltration','lateral_movement','privilege_escalation'],[0.3,0.25,0.25,0.2])]);

add('securonix-alert','securonix:alert','Securonix','SNYPR','json','Securonix UEBA alert',
  [F.ts,F.severity,F.user,F.src_ip],
  {src_ip:'src_ip',user:'user'},
  [F.risk,enumF('violation',['policy','threat_model','peer_group','behavioral'],[0.25,0.25,0.25,0.25])]);

add('hunters-alert','hunters:alert','Hunters','SOC Platform','json','Hunters SOC platform alert',
  [F.ts,F.severity,F.src_ip,F.user],
  {src_ip:'src_ip',user:'user'},
  [enumF('story_type',['cloud_threat','identity_threat','network_threat','endpoint_threat'],[0.25,0.25,0.25,0.25]),F.status]);

add('stellarcyber-alert','stellarcyber:alert','Stellar Cyber','Open XDR','json','Stellar Cyber Open XDR alert',
  [F.ts,F.severity,F.src_ip,F.dst_ip],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('kill_chain_stage',['reconnaissance','delivery','exploitation','installation','c2','actions'],[0.15,0.15,0.2,0.2,0.15,0.15]),F.risk]);

add('panther-alert','panther:alert','Panther','SIEM','json','Panther cloud SIEM alert',
  [F.ts,F.severity,F.user,F.src_ip],
  {src_ip:'src_ip',user:'user'},
  [enumF('log_type',['aws_cloudtrail','okta','github','gcp_audit','custom'],[0.25,0.2,0.2,0.15,0.2]),F.status]);

add('matano-alert','matano:alert','Matano','Cloud SIEM','json','Matano cloud-native SIEM alert',
  [F.ts,F.severity,F.src_ip],
  {src_ip:'src_ip'},
  [enumF('source',['cloudtrail','vpc_flow','route53','custom'],[0.3,0.25,0.25,0.2]),F.status]);

add('blumira-alert','blumira:alert','Blumira','SIEM','json','Blumira automated SIEM alert',
  [F.ts,F.severity,F.src_ip,F.user],
  {src_ip:'src_ip',user:'user'},
  [enumF('finding_type',['suspicious_login','malware','config_change','data_access'],[0.3,0.25,0.25,0.2]),F.status]);

add('gurucul-alert','gurucul:alert','Gurucul','UEBA','json','Gurucul UEBA analytics alert',
  [F.ts,F.severity,F.user,F.risk],
  {user:'user'},
  [enumF('model',['access_anomaly','behavior_anomaly','peer_deviation','risk_chain'],[0.25,0.25,0.25,0.25])]);

add('swimlane-event','swimlane:event','Swimlane','Turbine','json','Swimlane SOAR playbook event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('playbook_type',['incident_response','phishing','malware','enrichment','remediation'],[0.2,0.2,0.2,0.2,0.2]),F.id]);

add('tines-event','tines:event','Tines','Automation','json','Tines automation event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('story_type',['enrichment','triage','containment','notification','remediation'],[0.2,0.2,0.2,0.2,0.2]),F.id]);

add('torq-event','torq:event','Torq','Hyperautomation','json','Torq security automation event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('workflow',['alert_triage','threat_hunting','incident_response','compliance_check'],[0.3,0.25,0.25,0.2]),F.id]);

add('blink-event','blink:event','Blink','Security Automation','json','Blink security automation event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('automation_type',['cloud_security','identity','vulnerability','compliance'],[0.25,0.25,0.25,0.25]),F.id]);

add('shuffle-event','shuffle:event','Shuffle','SOAR','json','Shuffle open-source SOAR event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('workflow_status',['executing','success','failure','aborted'],[0.3,0.4,0.2,0.1]),F.id]);

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY — Threat Intel
// ═══════════════════════════════════════════════════════════════════════════════
add('recordedfuture-alert','recordedfuture:alert','Recorded Future','Intelligence','json','Recorded Future threat intel alert',
  [F.ts,F.severity,F.risk],
  {},
  [enumF('entity_type',['ip','domain','hash','vulnerability','url'],[0.2,0.2,0.2,0.2,0.2]),enumF('rule',['malware','c2','phishing','exploit','data_leak'],[0.2,0.2,0.2,0.2,0.2])]);

add('mandiant-alert','mandiant:alert','Mandiant','Advantage','json','Mandiant Advantage threat intel alert',
  [F.ts,F.severity],
  {},
  [enumF('ioc_type',['ip','domain','md5','sha256','url','email'],[0.2,0.15,0.15,0.2,0.15,0.15]),F.risk]);

add('virustotal-result','virustotal:result','VirusTotal','VT','json','VirusTotal scan result',
  [F.ts,F.verdict],
  {},
  [enumF('scan_type',['file','url','domain','ip'],[0.3,0.25,0.25,0.2]),intF('positives',0,70),intF('total_engines',60,75)]);

add('abuseipdb-report','abuseipdb:report','AbuseIPDB','AbuseIPDB','json','AbuseIPDB IP reputation report',
  [F.ts,F.src_ip],
  {src_ip:'src_ip'},
  [intF('abuse_confidence',0,100),enumF('category',['ssh_brute_force','web_spam','port_scan','ddos','phishing'],[0.25,0.2,0.2,0.2,0.15]),intF('total_reports',0,10000)]);

add('greynoise-result','greynoise:result','GreyNoise','Intelligence','json','GreyNoise IP classification result',
  [F.ts,F.src_ip],
  {src_ip:'src_ip'},
  [enumF('classification',['benign','malicious','unknown'],[0.3,0.3,0.4]),enumF('noise',['true','false'],[0.6,0.4])]);

add('shodan-result','shodan:result','Shodan','Shodan','json','Shodan host scan result',
  [F.ts,F.src_ip],
  {src_ip:'src_ip'},
  [intF('open_ports',1,20),enumF('os',['Linux','Windows','FreeBSD','embedded'],[0.4,0.3,0.15,0.15]),F.region]);

add('censys-result','censys:result','Censys','Search','json','Censys host discovery result',
  [F.ts,F.src_ip],
  {src_ip:'src_ip'},
  [enumF('service',['http','https','ssh','ftp','smtp','dns'],[0.2,0.2,0.2,0.15,0.15,0.1]),F.region]);

add('urlhaus-ioc','urlhaus:ioc','URLhaus','Abuse.ch','json','URLhaus malicious URL indicator',
  [F.ts],
  {},
  [enumF('url_status',['online','offline','unknown'],[0.3,0.5,0.2]),enumF('threat',['malware_download','phishing','cryptomining'],[0.5,0.3,0.2]),F.id]);

add('phishtank-ioc','phishtank:ioc','PhishTank','PhishTank','json','PhishTank phishing URL report',
  [F.ts],
  {},
  [enumF('verified',['yes','no'],[0.7,0.3]),enumF('target',['paypal','apple','microsoft','amazon','bank'],[0.25,0.2,0.2,0.2,0.15]),F.id]);

add('malwarebazaar-ioc','malwarebazaar:sample','MalwareBazaar','Abuse.ch','json','MalwareBazaar malware sample entry',
  [F.ts],
  {},
  [enumF('file_type',['exe','dll','doc','pdf','js','elf'],[0.25,0.2,0.15,0.15,0.15,0.1]),enumF('signature',['Emotet','QakBot','AgentTesla','Formbook','Cobalt Strike'],[0.2,0.2,0.2,0.2,0.2])]);

add('intelowl-result','intelowl:result','IntelOwl','IntelOwl','json','IntelOwl analysis result',
  [F.ts,F.verdict],
  {},
  [enumF('analyzer',['virustotal','abuseipdb','shodan','greynoise','misp'],[0.2,0.2,0.2,0.2,0.2]),F.status]);

add('opencti-indicator','opencti:indicator','OpenCTI','Platform','json','OpenCTI threat indicator',
  [F.ts,F.severity],
  {},
  [enumF('indicator_type',['ipv4','domain','file_hash','url','email'],[0.2,0.2,0.2,0.2,0.2]),enumF('pattern_type',['stix','yara','sigma','snort'],[0.35,0.25,0.2,0.2])]);

add('yeti-indicator','yeti:indicator','YETI','Platform','json','YETI threat intelligence indicator',
  [F.ts],
  {},
  [enumF('type',['ip','hostname','hash','url','email'],[0.2,0.2,0.2,0.2,0.2]),enumF('tag',['malware','c2','phishing','scanner','tor'],[0.2,0.2,0.2,0.2,0.2])]);

// ═══════════════════════════════════════════════════════════════════════════════
// CLOUD SERVICES — AWS
// ═══════════════════════════════════════════════════════════════════════════════
add('aws-inspector','aws:inspector','AWS','Inspector','json','AWS Inspector vulnerability finding',
  [F.ts,F.severity,F.status,F.region],
  {},
  [enumF('finding_type',['network_reachability','software_vulnerability','package_vulnerability'],[0.3,0.35,0.35]),intF('cvss_score',0,10)]);

add('aws-macie','aws:macie','AWS','Macie','json','AWS Macie sensitive data finding',
  [F.ts,F.severity,F.status,F.region],
  {},
  [enumF('finding_type',['sensitive_data','policy','credential_exposure'],[0.4,0.35,0.25]),enumF('data_type',['pii','financial','credentials','health','custom'],[0.25,0.2,0.2,0.15,0.2])]);

add('aws-securityhub','aws:securityhub','AWS','Security Hub','json','AWS Security Hub consolidated finding',
  [F.ts,F.severity,F.status,F.region],
  {},
  [enumF('product_name',['guardduty','inspector','macie','iam_analyzer','config'],[0.2,0.2,0.2,0.2,0.2]),enumF('compliance_status',['PASSED','FAILED','WARNING','NOT_AVAILABLE'],[0.4,0.3,0.2,0.1])]);

add('aws-sso','aws:sso','AWS','IAM Identity Center','json','AWS IAM Identity Center sign-in event',
  [F.ts,F.user,F.src_ip,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('auth_type',['password','mfa','sso','federated'],[0.3,0.25,0.25,0.2]),F.region]);

add('aws-organizations','aws:organizations','AWS','Organizations','json','AWS Organizations management event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('resource_type',['account','ou','policy','root'],[0.3,0.25,0.25,0.2]),F.region]);

add('aws-rds-audit','aws:rds:audit','AWS','RDS','json','AWS RDS database audit log',
  [F.ts,F.user,F.src_ip,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('statement_type',['SELECT','INSERT','UPDATE','DELETE','DDL','GRANT'],[0.3,0.2,0.15,0.1,0.15,0.1]),enumF('db_engine',['mysql','postgresql','oracle','sqlserver'],[0.3,0.3,0.2,0.2])]);

add('aws-redshift','aws:redshift','AWS','Redshift','json','AWS Redshift audit log',
  [F.ts,F.user,F.src_ip,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('query_type',['SELECT','INSERT','CREATE','ALTER','DROP','COPY'],[0.35,0.2,0.15,0.1,0.1,0.1]),F.duration]);

add('aws-emr','aws:emr','AWS','EMR','json','AWS EMR cluster event log',
  [F.ts,F.status,F.region],
  {},
  [enumF('event_type',['cluster_started','step_completed','step_failed','cluster_terminated','scaling'],[0.2,0.25,0.15,0.2,0.2]),F.id]);

add('aws-glue','aws:glue','AWS','Glue','json','AWS Glue ETL job event',
  [F.ts,F.status,F.region],
  {},
  [enumF('event_type',['job_started','job_succeeded','job_failed','crawler_completed','trigger_fired'],[0.2,0.25,0.15,0.2,0.2]),F.duration]);

add('aws-stepfunctions','aws:stepfunctions','AWS','Step Functions','json','AWS Step Functions execution event',
  [F.ts,F.status,F.region],
  {},
  [enumF('execution_status',['RUNNING','SUCCEEDED','FAILED','TIMED_OUT','ABORTED'],[0.25,0.35,0.15,0.1,0.15]),F.duration]);

add('aws-sqs','aws:sqs','AWS','SQS','json','AWS SQS queue event',
  [F.ts,F.user,F.action,F.region],
  {user:'user'},
  [enumF('api_call',['SendMessage','ReceiveMessage','DeleteMessage','CreateQueue','PurgeQueue'],[0.3,0.3,0.15,0.15,0.1]),intF('msg_count',1,1000)]);

add('aws-sns','aws:sns','AWS','SNS','json','AWS SNS notification event',
  [F.ts,F.user,F.action,F.status,F.region],
  {user:'user'},
  [enumF('event_type',['Publish','Subscribe','Unsubscribe','CreateTopic','DeleteTopic'],[0.35,0.2,0.15,0.15,0.15])]);

add('aws-kinesis','aws:kinesis','AWS','Kinesis','json','AWS Kinesis stream event',
  [F.ts,F.status,F.region],
  {},
  [enumF('api_call',['PutRecord','GetRecords','CreateStream','DescribeStream','SplitShard'],[0.3,0.3,0.15,0.15,0.1]),intF('records_count',1,10000)]);

add('aws-eventbridge','aws:eventbridge','AWS','EventBridge','json','AWS EventBridge event',
  [F.ts,F.status,F.region],
  {},
  [enumF('source',['aws.ec2','aws.s3','aws.iam','aws.rds','custom.app'],[0.2,0.2,0.2,0.2,0.2]),enumF('detail_type',['state_change','api_call','scheduled','custom'],[0.3,0.25,0.25,0.2])]);

add('aws-appsync','aws:appsync','AWS','AppSync','json','AWS AppSync GraphQL request log',
  [F.ts,F.user,F.src_ip,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('operation',['query','mutation','subscription'],[0.5,0.35,0.15]),F.duration]);

add('aws-cognito','aws:cognito','AWS','Cognito','json','AWS Cognito user pool event',
  [F.ts,F.user,F.src_ip,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('event_type',['SignIn','SignUp','ForgotPassword','TokenRefresh','AdminAction'],[0.3,0.2,0.15,0.2,0.15]),enumF('auth_flow',['USER_PASSWORD','SRP','CUSTOM','REFRESH_TOKEN'],[0.3,0.3,0.15,0.25])]);

add('aws-iot','aws:iot','AWS','IoT Core','json','AWS IoT Core event log',
  [F.ts,F.status],
  {},
  [enumF('event_type',['connect','disconnect','publish','subscribe','shadow_update'],[0.2,0.15,0.25,0.2,0.2]),enumF('protocol',['mqtt','https','wss'],[0.5,0.3,0.2])]);

add('aws-eks','aws:eks','AWS','EKS','json','AWS EKS cluster audit log',
  [F.ts,F.user,F.src_ip,F.status,F.region],
  {src_ip:'src_ip',user:'user'},
  [enumF('verb',['get','list','create','update','delete','watch'],[0.25,0.2,0.15,0.15,0.1,0.15]),enumF('resource',['pods','deployments','services','configmaps','secrets'],[0.25,0.2,0.2,0.2,0.15])]);

add('aws-secretsmanager','aws:secretsmanager','AWS','Secrets Manager','json','AWS Secrets Manager audit event',
  [F.ts,F.user,F.src_ip,F.action,F.status,F.region],
  {src_ip:'src_ip',user:'user'},
  [enumF('api',['GetSecretValue','CreateSecret','UpdateSecret','DeleteSecret','RotateSecret'],[0.35,0.2,0.15,0.15,0.15])]);

add('aws-ssm','aws:ssm','AWS','Systems Manager','json','AWS Systems Manager event',
  [F.ts,F.user,F.status,F.region],
  {user:'user'},
  [enumF('doc_type',['RunCommand','Automation','Session','Patch','Inventory'],[0.25,0.2,0.2,0.2,0.15]),F.hostname]);

// ═══════════════════════════════════════════════════════════════════════════════
// CLOUD SERVICES — Azure
// ═══════════════════════════════════════════════════════════════════════════════
add('azure-sql-audit','azure:sql:audit','Microsoft','Azure SQL','json','Azure SQL Database audit log',
  [F.ts,F.user,F.src_ip,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('action_name',['SELECT','INSERT','UPDATE','DELETE','EXECUTE','LOGIN'],[0.3,0.15,0.15,0.1,0.15,0.15]),enumF('database_name',['maindb','userdb','analyticsdb','logsdb'],[0.3,0.25,0.25,0.2])]);

add('azure-appservice','azure:appservice','Microsoft','App Service','json','Azure App Service diagnostic log',
  [F.ts,F.src_ip,F.method,F.code,F.duration],
  {src_ip:'src_ip'},
  [enumF('site_name',['web-app-prod','api-prod','portal-prod','admin-prod'],[0.3,0.3,0.2,0.2])]);

add('azure-aci','azure:aci','Microsoft','Container Instances','json','Azure Container Instances event',
  [F.ts,F.status],
  {},
  [enumF('event_type',['container_started','container_stopped','container_failed','pull_image','exec'],[0.25,0.2,0.15,0.2,0.2]),F.region]);

add('azure-devops','azure:devops','Microsoft','Azure DevOps','json','Azure DevOps audit log',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('area',['git','build','release','work_items','permissions'],[0.2,0.2,0.2,0.2,0.2])]);

add('azure-dns','azure:dns','Microsoft','Azure DNS','json','Azure DNS query log',
  [F.ts,F.client_ip],
  {src_ip:'client_ip'},
  [enumF('query_type',['A','AAAA','CNAME','MX','TXT','NS'],[0.3,0.15,0.2,0.15,0.1,0.1]),enumF('response_code',['NOERROR','NXDOMAIN','SERVFAIL','REFUSED'],[0.7,0.15,0.1,0.05])]);

add('azure-frontdoor','azure:frontdoor','Microsoft','Front Door','json','Azure Front Door access log',
  [F.ts,F.client_ip,F.method,F.code,F.bytes,F.duration],
  {src_ip:'client_ip'},
  [enumF('routing_rule',['default','api','static','websocket'],[0.3,0.3,0.25,0.15])]);

add('azure-logicapps','azure:logicapps','Microsoft','Logic Apps','json','Azure Logic Apps run event',
  [F.ts,F.status,F.duration],
  {},
  [enumF('trigger_type',['http','recurrence','queue','event_grid','manual'],[0.25,0.25,0.2,0.15,0.15]),F.id]);

add('azure-monitor','azure:monitor','Microsoft','Azure Monitor','json','Azure Monitor alert event',
  [F.ts,F.severity,F.status],
  {},
  [enumF('signal_type',['metric','log','activity_log','smart_detector'],[0.3,0.25,0.25,0.2]),enumF('resource_type',['vm','sql','storage','app_service','aks'],[0.25,0.2,0.2,0.2,0.15])]);

add('azure-policy','azure:policy','Microsoft','Azure Policy','json','Azure Policy compliance event',
  [F.ts,F.status],
  {},
  [enumF('effect',['audit','deny','append','deployIfNotExists','disabled'],[0.3,0.25,0.2,0.15,0.1]),enumF('compliance_state',['Compliant','NonCompliant','Exempt','Unknown'],[0.5,0.3,0.1,0.1])]);

add('azure-resourcegraph','azure:resourcegraph','Microsoft','Resource Graph','json','Azure Resource Graph query log',
  [F.ts,F.user,F.status,F.duration],
  {user:'user'},
  [enumF('query_type',['resources','resourcechanges','resourcecontainers'],[0.5,0.3,0.2]),intF('result_count',0,10000)]);

add('azure-servicebus','azure:servicebus','Microsoft','Service Bus','json','Azure Service Bus operational log',
  [F.ts,F.status],
  {},
  [enumF('operation',['Send','Receive','Complete','Abandon','DeadLetter'],[0.3,0.25,0.2,0.15,0.1]),intF('message_count',1,1000)]);

add('azure-signalr','azure:signalr','Microsoft','SignalR','json','Azure SignalR service event',
  [F.ts,F.status],
  {},
  [enumF('event_type',['connected','disconnected','message_sent','message_received'],[0.25,0.2,0.3,0.25]),intF('connection_count',1,10000)]);

add('azure-trafficmanager','azure:trafficmanager','Microsoft','Traffic Manager','json','Azure Traffic Manager probe event',
  [F.ts,F.status],
  {},
  [enumF('probe_result',['online','degraded','inactive','disabled'],[0.6,0.2,0.1,0.1]),enumF('routing_method',['performance','priority','weighted','geographic'],[0.3,0.25,0.25,0.2])]);

add('azure-apim','azure:apim','Microsoft','API Management','json','Azure API Management request log',
  [F.ts,F.client_ip,F.method,F.code,F.duration,F.user],
  {src_ip:'client_ip',user:'user'},
  [enumF('api_name',['orders-api','users-api','catalog-api','auth-api'],[0.3,0.25,0.25,0.2])]);

add('azure-cognitiveservices','azure:cognitive','Microsoft','Cognitive Services','json','Azure Cognitive Services usage log',
  [F.ts,F.status,F.duration],
  {},
  [enumF('service_type',['text_analytics','computer_vision','speech','language','openai'],[0.2,0.2,0.2,0.2,0.2]),intF('units_consumed',1,1000)]);

add('azure-datafactory','azure:datafactory','Microsoft','Data Factory','json','Azure Data Factory pipeline run event',
  [F.ts,F.status,F.duration],
  {},
  [enumF('run_type',['pipeline','activity','trigger','debug'],[0.3,0.3,0.25,0.15]),F.id]);

// ═══════════════════════════════════════════════════════════════════════════════
// CLOUD SERVICES — GCP
// ═══════════════════════════════════════════════════════════════════════════════
add('gcp-vpcflow','gcp:vpcflow','Google','VPC Flow Logs','json','GCP VPC flow log',
  [F.ts,F.src_ip,F.dst_ip,F.proto,F.port,F.bytes],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [F.direction,F.region]);

add('gcp-dns','gcp:dns','Google','Cloud DNS','json','GCP Cloud DNS query log',
  [F.ts,F.client_ip],
  {src_ip:'client_ip'},
  [enumF('query_type',['A','AAAA','CNAME','MX','TXT'],[0.35,0.15,0.2,0.15,0.15]),enumF('response_code',['NOERROR','NXDOMAIN','SERVFAIL'],[0.7,0.2,0.1])]);

add('gcp-cloudsql','gcp:cloudsql','Google','Cloud SQL','json','GCP Cloud SQL audit log',
  [F.ts,F.user,F.src_ip,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('statement_type',['SELECT','INSERT','UPDATE','DELETE','DDL'],[0.35,0.2,0.15,0.1,0.2]),enumF('db_type',['mysql','postgresql'],[0.5,0.5])]);

add('gcp-bigquery-audit','gcp:bigquery:audit','Google','BigQuery','json','GCP BigQuery audit log',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('method',['jobservice.insert','tabledata.list','datasets.get','tables.get'],[0.35,0.25,0.2,0.2]),F.duration]);

add('gcp-cloudfunctions','gcp:functions','Google','Cloud Functions','json','GCP Cloud Functions execution log',
  [F.ts,F.status,F.duration,F.region],
  {},
  [enumF('trigger',['http','pubsub','storage','firestore','scheduler'],[0.3,0.2,0.2,0.15,0.15]),intF('memory_mb',128,4096)]);

add('gcp-pubsub','gcp:pubsub','Google','Pub/Sub','json','GCP Pub/Sub audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('method',['Publish','Pull','Acknowledge','CreateSubscription','CreateTopic'],[0.3,0.25,0.2,0.15,0.1]),intF('message_count',1,10000)]);

add('gcp-cloudarmor','gcp:cloudarmor','Google','Cloud Armor','json','GCP Cloud Armor WAF log',
  [F.ts,F.client_ip,F.action,F.severity],
  {src_ip:'client_ip'},
  [enumF('rule_type',['rate_limiting','geo_blocking','waf','custom'],[0.25,0.2,0.3,0.25]),F.code]);

add('gcp-kms','gcp:kms','Google','Cloud KMS','json','GCP Cloud KMS audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('method',['Encrypt','Decrypt','CreateCryptoKey','GetCryptoKey','Destroy'],[0.3,0.3,0.15,0.15,0.1])]);

add('gcp-iap','gcp:iap','Google','Identity-Aware Proxy','json','GCP IAP access log',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('access_level',['allowed','denied','mfa_required','conditional'],[0.5,0.2,0.15,0.15])]);

add('gcp-dataflow','gcp:dataflow','Google','Dataflow','json','GCP Dataflow job event',
  [F.ts,F.status,F.duration,F.region],
  {},
  [enumF('job_state',['RUNNING','DONE','FAILED','CANCELLED','UPDATED'],[0.3,0.3,0.15,0.1,0.15]),F.id]);

add('gcp-anthos','gcp:anthos','Google','Anthos','json','GCP Anthos cluster event',
  [F.ts,F.status,F.hostname],
  {},
  [enumF('event_type',['cluster_registered','config_sync','policy_audit','mesh_event'],[0.25,0.25,0.25,0.25]),F.region]);

add('gcp-chronicle','gcp:chronicle','Google','Chronicle','json','Google Chronicle SIEM event',
  [F.ts,F.severity,F.src_ip,F.user],
  {src_ip:'src_ip',user:'user'},
  [enumF('rule_type',['detection','alert','indicator','entity'],[0.3,0.25,0.25,0.2]),F.risk]);

// ═══════════════════════════════════════════════════════════════════════════════
// CLOUD SERVICES — SaaS
// ═══════════════════════════════════════════════════════════════════════════════
const saasApps = [
  ['workday-audit','workday:audit','Workday','HCM','Workday HCM audit event',[F.ts,F.user,F.action,F.status,F.src_ip],[enumF('module',['hcm','finance','recruiting','learning','payroll'],[0.25,0.2,0.2,0.2,0.15])]],
  ['sap-audit','sap:audit','SAP','ERP','SAP ERP audit log',[F.ts,F.user,F.action,F.status,F.src_ip],[enumF('tcode',['SU01','SM21','SE16','PFCG','SCC4'],[0.2,0.2,0.2,0.2,0.2])]],
  ['oracle-cloud-audit','oracle:cloud:audit','Oracle','Cloud','Oracle Cloud audit event',[F.ts,F.user,F.action,F.status,F.region],[enumF('service',['iam','compute','networking','storage','database'],[0.2,0.2,0.2,0.2,0.2])]],
  ['atlassian-access','atlassian:access','Atlassian','Access','Atlassian Access audit log',[F.ts,F.user,F.action,F.status,F.src_ip],[enumF('product',['jira','confluence','bitbucket','trello'],[0.3,0.25,0.25,0.2])]],
  ['confluence-audit','confluence:audit','Atlassian','Confluence','Confluence audit event',[F.ts,F.user,F.action,F.status],[enumF('space',['engineering','product','hr','sales'],[0.3,0.25,0.25,0.2])]],
  ['trello-audit','trello:audit','Atlassian','Trello','Trello board audit event',[F.ts,F.user,F.action,F.status],[enumF('board_type',['project','kanban','scrum','personal'],[0.3,0.25,0.25,0.2])]],
  ['asana-audit','asana:audit','Asana','Asana','Asana workspace audit log',[F.ts,F.user,F.action,F.status],[enumF('resource_type',['task','project','portfolio','goal'],[0.3,0.25,0.25,0.2])]],
  ['monday-audit','monday:audit','Monday','Monday.com','Monday.com audit event',[F.ts,F.user,F.action,F.status],[enumF('board_kind',['private','public','shareable'],[0.35,0.35,0.3])]],
  ['notion-audit','notion:audit','Notion','Notion','Notion workspace audit event',[F.ts,F.user,F.action,F.status],[enumF('object_type',['page','database','workspace','integration'],[0.3,0.25,0.25,0.2])]],
  ['airtable-audit','airtable:audit','Airtable','Airtable','Airtable audit log',[F.ts,F.user,F.action,F.status],[enumF('resource',['base','table','view','automation'],[0.3,0.25,0.25,0.2])]],
  ['figma-audit','figma:audit','Figma','Figma','Figma audit log',[F.ts,F.user,F.action,F.status],[enumF('file_type',['design','figjam','prototype','component'],[0.35,0.25,0.2,0.2])]],
  ['canva-audit','canva:audit','Canva','Canva','Canva team audit log',[F.ts,F.user,F.action,F.status],[enumF('design_type',['presentation','social_media','document','print'],[0.3,0.25,0.25,0.2])]],
  ['dropbox-audit','dropbox:audit','Dropbox','Business','Dropbox Business audit log',[F.ts,F.user,F.action,F.status,F.src_ip],[enumF('category',['file_operations','sharing','login','admin','legal_holds'],[0.3,0.2,0.2,0.15,0.15])]],
  ['google-workspace','google:workspace','Google','Workspace','Google Workspace admin audit log',[F.ts,F.user,F.action,F.status,F.src_ip],[enumF('service',['drive','gmail','calendar','admin','meet'],[0.25,0.2,0.2,0.2,0.15])]],
  ['hubspot-audit','hubspot:audit','HubSpot','CRM','HubSpot CRM audit log',[F.ts,F.user,F.action,F.status],[enumF('object_type',['contact','deal','company','ticket','email'],[0.25,0.2,0.2,0.2,0.15])]],
  ['intercom-event','intercom:event','Intercom','Intercom','Intercom admin event log',[F.ts,F.user,F.action,F.status],[enumF('channel',['chat','email','phone','messenger'],[0.3,0.25,0.25,0.2])]],
  ['drift-event','drift:event','Drift','Drift','Drift conversation event',[F.ts,F.user,F.action,F.status],[enumF('conversation_type',['chat','video','email','playbook'],[0.35,0.2,0.25,0.2])]],
  ['segment-event','segment:event','Segment','CDP','Segment CDP event log',[F.ts,F.user,F.action,F.status],[enumF('event_type',['track','identify','page','group','alias'],[0.3,0.25,0.2,0.15,0.1])]],
  ['amplitude-event','amplitude:event','Amplitude','Analytics','Amplitude analytics event',[F.ts,F.user,F.status],[enumF('event_category',['pageview','click','conversion','error','session'],[0.3,0.2,0.2,0.15,0.15])]],
  ['mixpanel-event','mixpanel:event','Mixpanel','Analytics','Mixpanel analytics event',[F.ts,F.user,F.status],[enumF('event_type',['track','engage','import','export'],[0.4,0.25,0.2,0.15])]],
  ['launchdarkly-audit','launchdarkly:audit','LaunchDarkly','Feature Flags','LaunchDarkly audit log',[F.ts,F.user,F.action,F.status],[enumF('resource',['flag','segment','project','environment'],[0.35,0.25,0.2,0.2])]],
  ['split-event','split:event','Split','Feature Flags','Split feature flag event',[F.ts,F.user,F.action,F.status],[enumF('impression',['on','off','control'],[0.45,0.4,0.15])]],
  ['datadog-apm','datadog:apm','Datadog','APM','Datadog APM trace event',[F.ts,F.status,F.duration],[enumF('service',['web','api','worker','database','cache'],[0.25,0.25,0.2,0.15,0.15]),F.code]],
  ['sentry-event','sentry:event','Sentry','Error Tracking','Sentry error event',[F.ts,F.severity,F.status],[enumF('platform',['javascript','python','java','ruby','go'],[0.3,0.25,0.2,0.15,0.1]),enumF('error_type',['TypeError','ValueError','RuntimeError','ConnectionError'],[0.3,0.25,0.25,0.2])]],
  ['bugsnag-event','bugsnag:event','Bugsnag','Error Monitoring','Bugsnag error event',[F.ts,F.severity,F.status],[enumF('platform',['android','ios','javascript','ruby','python'],[0.2,0.2,0.25,0.2,0.15])]],
  ['logrocket-event','logrocket:event','LogRocket','Session Replay','LogRocket session event',[F.ts,F.user,F.status],[enumF('event_type',['error','rage_click','dead_click','network_error'],[0.3,0.25,0.25,0.2])]],
  ['fullstory-event','fullstory:event','FullStory','DX Analytics','FullStory session event',[F.ts,F.user,F.status],[enumF('signal',['rage_click','error_click','dead_click','thrashed_cursor'],[0.3,0.25,0.25,0.2])]],
  ['heap-event','heap:event','Heap','Analytics','Heap analytics event',[F.ts,F.user,F.status],[enumF('event_type',['pageview','click','submit','change','custom'],[0.25,0.25,0.2,0.15,0.15])]],
  ['snowflake-audit','snowflake:audit','Snowflake','Data Cloud','Snowflake query audit log',[F.ts,F.user,F.status,F.duration],[enumF('query_type',['SELECT','INSERT','CREATE','COPY','MERGE'],[0.35,0.2,0.15,0.15,0.15])]],
  ['databricks-audit','databricks:audit','Databricks','Lakehouse','Databricks audit log',[F.ts,F.user,F.action,F.status],[enumF('service',['clusters','notebooks','jobs','sql','mlflow'],[0.2,0.2,0.2,0.2,0.2])]],
  ['dbt-cloud-event','dbt:cloud','dbt Labs','dbt Cloud','dbt Cloud run event',[F.ts,F.user,F.status,F.duration],[enumF('command',['run','test','build','source_freshness'],[0.35,0.25,0.25,0.15])]],
  ['fivetran-event','fivetran:event','Fivetran','Data Integration','Fivetran sync event',[F.ts,F.status,F.duration],[enumF('connector_type',['database','saas','file','event','function'],[0.25,0.3,0.15,0.15,0.15])]],
  ['airbyte-event','airbyte:event','Airbyte','Data Integration','Airbyte sync event',[F.ts,F.status,F.duration],[enumF('sync_mode',['full_refresh','incremental','cdc'],[0.3,0.4,0.3])]],
  ['hightouch-event','hightouch:event','Hightouch','Reverse ETL','Hightouch sync event',[F.ts,F.status,F.duration],[enumF('destination',['salesforce','hubspot','google_ads','facebook'],[0.3,0.25,0.25,0.2])]],
  ['census-event','census:event','Census','Reverse ETL','Census sync event',[F.ts,F.status,F.duration],[enumF('model_type',['sql','dbt','table','custom'],[0.3,0.25,0.25,0.2])]],
  ['braze-event','braze:event','Braze','Customer Engagement','Braze campaign event',[F.ts,F.user,F.status],[enumF('channel',['push','email','in_app','sms','content_card'],[0.2,0.25,0.2,0.2,0.15])]],
  ['iterable-event','iterable:event','Iterable','Marketing','Iterable campaign event',[F.ts,F.user,F.status],[enumF('message_type',['email','push','sms','in_app','web_push'],[0.25,0.2,0.2,0.2,0.15])]],
  ['customerio-event','customerio:event','Customer.io','Messaging','Customer.io messaging event',[F.ts,F.user,F.status],[enumF('action_type',['sent','delivered','opened','clicked','bounced'],[0.2,0.25,0.2,0.2,0.15])]],
  ['mailchimp-event','mailchimp:event','Mailchimp','Email Marketing','Mailchimp campaign event',[F.ts,F.user,F.status],[enumF('activity',['send','open','click','bounce','unsubscribe'],[0.2,0.25,0.25,0.15,0.15])]],
  ['stripe-event','stripe:event','Stripe','Payments','Stripe payment event',[F.ts,F.user,F.status],[enumF('event_type',['charge.succeeded','charge.failed','refund.created','dispute.created','payout.paid'],[0.4,0.15,0.15,0.1,0.2]),intF('amount_cents',100,100000)]],
  ['square-event','square:event','Square','Payments','Square payment event',[F.ts,F.user,F.status],[enumF('event_type',['payment.completed','refund.created','order.created','invoice.sent'],[0.4,0.2,0.2,0.2])]],
  ['shopify-audit','shopify:audit','Shopify','Commerce','Shopify admin audit log',[F.ts,F.user,F.action,F.status],[enumF('resource',['order','product','customer','discount','theme'],[0.25,0.2,0.2,0.2,0.15])]],
  ['woocommerce-event','woocommerce:event','WooCommerce','Commerce','WooCommerce store event',[F.ts,F.user,F.status],[enumF('event_type',['order_created','order_updated','product_updated','refund_created'],[0.3,0.25,0.25,0.2])]],
  ['bigcommerce-event','bigcommerce:event','BigCommerce','Commerce','BigCommerce store event',[F.ts,F.user,F.action,F.status],[enumF('resource',['orders','products','customers','coupons'],[0.3,0.25,0.25,0.2])]],
  ['contentful-audit','contentful:audit','Contentful','CMS','Contentful content audit log',[F.ts,F.user,F.action,F.status],[enumF('entity_type',['entry','asset','content_type','environment'],[0.3,0.25,0.25,0.2])]],
  ['sanity-audit','sanity:audit','Sanity','CMS','Sanity CMS audit log',[F.ts,F.user,F.action,F.status],[enumF('mutation_type',['create','createOrReplace','patch','delete'],[0.25,0.25,0.3,0.2])]],
  ['strapi-audit','strapi:audit','Strapi','CMS','Strapi headless CMS audit log',[F.ts,F.user,F.action,F.status],[enumF('model',['article','page','user','media','role'],[0.25,0.2,0.2,0.2,0.15])]],
  ['cloudflare-workers','cloudflare:workers','Cloudflare','Workers','Cloudflare Workers event log',[F.ts,F.status,F.duration],[enumF('event_type',['fetch','scheduled','queue','email'],[0.4,0.25,0.2,0.15]),F.code]],
  ['vercel-event','vercel:event','Vercel','Platform','Vercel deployment event',[F.ts,F.user,F.status],[enumF('event_type',['deployment','domain','env_variable','function_invocation'],[0.3,0.25,0.2,0.25])]],
  ['netlify-event','netlify:event','Netlify','Platform','Netlify deployment event',[F.ts,F.user,F.status],[enumF('event_type',['deploy','build','function','form_submission'],[0.3,0.25,0.25,0.2])]],
  ['render-event','render:event','Render','Cloud','Render service event',[F.ts,F.status],[enumF('service_type',['web','worker','cron','database','static'],[0.25,0.2,0.2,0.2,0.15])]],
  ['railway-event','railway:event','Railway','Platform','Railway deployment event',[F.ts,F.user,F.status],[enumF('event_type',['deploy','build','restart','variable_update'],[0.3,0.25,0.25,0.2])]],
  ['flyio-event','flyio:event','Fly.io','Platform','Fly.io machine event',[F.ts,F.status,F.region],[enumF('event_type',['started','stopped','replaced','scaled','health_check'],[0.25,0.2,0.2,0.2,0.15])]],
  ['supabase-event','supabase:event','Supabase','Platform','Supabase project event',[F.ts,F.user,F.action,F.status],[enumF('service',['auth','database','storage','functions','realtime'],[0.2,0.25,0.2,0.2,0.15])]],
  ['planetscale-audit','planetscale:audit','PlanetScale','Database','PlanetScale audit log',[F.ts,F.user,F.action,F.status],[enumF('resource',['branch','deploy_request','schema','backup'],[0.3,0.25,0.25,0.2])]],
  ['neon-audit','neon:audit','Neon','Database','Neon serverless Postgres audit log',[F.ts,F.user,F.action,F.status],[enumF('resource',['project','branch','endpoint','database'],[0.3,0.25,0.25,0.2])]],
  ['cockroachdb-audit','cockroachdb:audit','Cockroach Labs','CockroachDB','CockroachDB audit log',[F.ts,F.user,F.src_ip,F.status],[enumF('statement_type',['SELECT','INSERT','UPDATE','DELETE','ALTER'],[0.3,0.2,0.2,0.15,0.15])]],
  ['mongodb-atlas-audit','mongodb:atlas','MongoDB','Atlas','MongoDB Atlas audit log',[F.ts,F.user,F.src_ip,F.status],[enumF('auth_result',['success','failure'],[0.8,0.2]),enumF('command',['find','insert','update','delete','aggregate'],[0.3,0.2,0.15,0.15,0.2])]],
  ['redis-cloud-event','redis:cloud','Redis','Cloud','Redis Cloud event log',[F.ts,F.user,F.action,F.status],[enumF('resource',['database','subscription','account','alert'],[0.35,0.25,0.2,0.2])]],
  ['confluent-cloud','confluent:cloud','Confluent','Cloud','Confluent Cloud audit log',[F.ts,F.user,F.action,F.status],[enumF('resource',['cluster','topic','connector','schema_registry','ksqldb'],[0.2,0.25,0.2,0.2,0.15])]],
  ['pulsar-event','pulsar:event','Apache','Pulsar','Apache Pulsar event log',[F.ts,F.status],[enumF('event_type',['produce','consume','subscribe','unsubscribe','acknowledge'],[0.25,0.25,0.2,0.15,0.15]),intF('msg_count',1,10000)]],
  ['rabbitmq-cloud','rabbitmq:cloud','CloudAMQP','RabbitMQ','CloudAMQP RabbitMQ event log',[F.ts,F.user,F.status],[enumF('event_type',['publish','consume','queue_created','exchange_created','binding_created'],[0.3,0.25,0.15,0.15,0.15])]],
  ['elastic-cloud-audit','elastic:cloud:audit','Elastic','Cloud','Elastic Cloud audit log',[F.ts,F.user,F.action,F.status],[enumF('resource',['deployment','cluster','kibana','apm','enterprise_search'],[0.25,0.2,0.2,0.2,0.15])]],
];

for (const [filename, sourcetype, vendor, product, desc, fields, extra] of saasApps) {
  add(filename, sourcetype, vendor, product, 'json', desc, fields, {src_ip: fields.some(f=>f.name==='src_ip')?'src_ip':undefined, user: fields.some(f=>f.name==='user')?'user':undefined}, extra);
}

// ═══════════════════════════════════════════════════════════════════════════════
// INFRASTRUCTURE — Web Servers
// ═══════════════════════════════════════════════════════════════════════════════
add('caddy-access','caddy:access','Caddy','Caddy','json','Caddy web server access log',
  [F.ts,F.client_ip,F.method,F.code,F.bytes,F.duration],
  {src_ip:'client_ip'},
  [enumF('host',['www.example.com','api.example.com','admin.example.com'],[0.4,0.35,0.25])]);

add('litespeed-access','litespeed:access','LiteSpeed','LiteSpeed','syslog','LiteSpeed access log',
  [F.ts,F.client_ip,F.method,F.code,F.bytes],
  {src_ip:'client_ip'},
  [enumF('vhost',['site1.com','site2.com','site3.com'],[0.4,0.35,0.25])]);

add('tomcat-access','tomcat:access','Apache','Tomcat','json','Apache Tomcat access log',
  [F.ts,F.client_ip,F.method,F.code,F.bytes,F.duration,F.user],
  {src_ip:'client_ip',user:'user'},
  [enumF('webapp',['ROOT','api','admin','docs'],[0.3,0.3,0.2,0.2])]);

add('jetty-access','jetty:access','Eclipse','Jetty','json','Eclipse Jetty access log',
  [F.ts,F.client_ip,F.method,F.code,F.bytes,F.duration],
  {src_ip:'client_ip'},
  [enumF('context',['root','api','ws','admin'],[0.3,0.3,0.2,0.2])]);

add('gunicorn-access','gunicorn:access','Gunicorn','Gunicorn','json','Gunicorn WSGI access log',
  [F.ts,F.client_ip,F.method,F.code,F.bytes,F.duration],
  {src_ip:'client_ip'},
  [intF('worker_pid',1000,65000)]);

add('uwsgi-access','uwsgi:access','uWSGI','uWSGI','json','uWSGI access log',
  [F.ts,F.client_ip,F.method,F.code,F.bytes,F.duration],
  {src_ip:'client_ip'},
  [intF('worker_id',1,16)]);

add('passenger-access','passenger:access','Phusion','Passenger','json','Phusion Passenger access log',
  [F.ts,F.client_ip,F.method,F.code,F.bytes,F.duration],
  {src_ip:'client_ip'},
  [intF('process_count',1,32)]);

add('varnish-access','varnish:access','Varnish','Cache','syslog','Varnish cache access log',
  [F.ts,F.client_ip,F.method,F.code,F.bytes],
  {src_ip:'client_ip'},
  [enumF('hit_type',['hit','miss','pass','pipe','synth'],[0.4,0.25,0.2,0.1,0.05])]);

add('pound-access','pound:access','Pound','Proxy','syslog','Pound reverse proxy access log',
  [F.ts,F.client_ip,F.method,F.code,F.bytes],
  {src_ip:'client_ip'},
  [enumF('backend',['backend1','backend2','backend3'],[0.4,0.35,0.25])]);

add('cherokee-access','cherokee:access','Cherokee','Web Server','syslog','Cherokee web server access log',
  [F.ts,F.client_ip,F.method,F.code,F.bytes],
  {src_ip:'client_ip'},
  [enumF('handler',['file','cgi','proxy','redirect'],[0.35,0.25,0.25,0.15])]);

// ═══════════════════════════════════════════════════════════════════════════════
// INFRASTRUCTURE — Databases
// ═══════════════════════════════════════════════════════════════════════════════
add('couchdb-log','couchdb:log','Apache','CouchDB','json','CouchDB log event',
  [F.ts,F.level,F.user,F.src_ip],
  {src_ip:'src_ip',user:'user'},
  [enumF('method',['GET','PUT','POST','DELETE','COPY'],[0.3,0.2,0.2,0.15,0.15]),F.code]);

add('cassandra-log','cassandra:log','Apache','Cassandra','json','Cassandra database log',
  [F.ts,F.level,F.hostname],
  {},
  [enumF('component',['compaction','gossip','storage','commit_log','repair'],[0.25,0.2,0.2,0.2,0.15]),F.msg]);

add('neo4j-log','neo4j:log','Neo4j','Graph Database','json','Neo4j database log',
  [F.ts,F.level,F.user],
  {user:'user'},
  [enumF('event_type',['query','transaction','security','cluster','checkpoint'],[0.3,0.2,0.2,0.15,0.15]),F.duration]);

add('influxdb-log','influxdb:log','InfluxData','InfluxDB','json','InfluxDB database log',
  [F.ts,F.level],
  {},
  [enumF('service',['write','query','retention','compaction','wal'],[0.25,0.25,0.2,0.15,0.15]),F.duration]);

add('timescaledb-log','timescaledb:log','Timescale','TimescaleDB','json','TimescaleDB log event',
  [F.ts,F.level,F.user,F.status],
  {user:'user'},
  [enumF('operation',['query','compression','retention','continuous_aggregate'],[0.3,0.25,0.25,0.2]),F.duration]);

add('clickhouse-log','clickhouse:log','ClickHouse','ClickHouse','json','ClickHouse database log',
  [F.ts,F.level,F.user,F.status],
  {user:'user'},
  [enumF('query_type',['SELECT','INSERT','CREATE','ALTER','SYSTEM'],[0.3,0.25,0.15,0.15,0.15]),F.duration]);

add('scylladb-log','scylladb:log','ScyllaDB','ScyllaDB','json','ScyllaDB log event',
  [F.ts,F.level,F.hostname],
  {},
  [enumF('component',['compaction','gossip','storage','cql','repair'],[0.25,0.2,0.2,0.2,0.15]),F.msg]);

add('yugabytedb-log','yugabytedb:log','YugabyteDB','YugabyteDB','json','YugabyteDB log event',
  [F.ts,F.level,F.hostname],
  {},
  [enumF('service',['tserver','master','yql','ysql','cdc'],[0.25,0.2,0.2,0.2,0.15]),F.msg]);

add('tidb-log','tidb:log','PingCAP','TiDB','json','TiDB database log',
  [F.ts,F.level],
  {},
  [enumF('component',['tidb','tikv','pd','tiflash','ticdc'],[0.25,0.2,0.2,0.2,0.15]),F.msg]);

add('vitess-log','vitess:log','Vitess','Vitess','json','Vitess database log',
  [F.ts,F.level,F.user],
  {user:'user'},
  [enumF('component',['vtgate','vttablet','vtctld','vtctl'],[0.3,0.3,0.2,0.2]),F.msg]);

add('mariadb-audit','mariadb:audit','MariaDB','MariaDB','json','MariaDB audit log',
  [F.ts,F.user,F.src_ip,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('query_type',['SELECT','INSERT','UPDATE','DELETE','CONNECT','DISCONNECT'],[0.25,0.15,0.15,0.1,0.2,0.15]),enumF('database',['app_db','users_db','logs_db','metrics_db'],[0.3,0.25,0.25,0.2])]);

add('db2-audit','db2:audit','IBM','DB2','json','IBM DB2 audit log',
  [F.ts,F.user,F.src_ip,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('category',['AUDIT','CHECKING','OBJMAINT','SECMAINT','SYSADMIN','VALIDATE'],[0.15,0.2,0.15,0.2,0.15,0.15])]);

add('teradata-audit','teradata:audit','Teradata','Teradata','json','Teradata database audit log',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('statement_type',['SELECT','INSERT','MERGE','COLLECT','GRANT'],[0.3,0.2,0.2,0.15,0.15]),F.duration]);

add('greenplum-log','greenplum:log','VMware','Greenplum','json','Greenplum database log',
  [F.ts,F.user,F.level,F.status],
  {user:'user'},
  [enumF('command_tag',['SELECT','INSERT','COPY','CREATE','ANALYZE'],[0.3,0.2,0.2,0.15,0.15]),F.duration]);

add('vertica-audit','vertica:audit','Micro Focus','Vertica','json','Vertica analytics audit log',
  [F.ts,F.user,F.src_ip,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('query_type',['QUERY','DML','DDL','UTILITY','TRANSACTION'],[0.3,0.2,0.2,0.15,0.15]),F.duration]);

add('trino-log','trino:log','Trino','Trino','json','Trino query log',
  [F.ts,F.user,F.status,F.duration],
  {user:'user'},
  [enumF('query_state',['QUEUED','RUNNING','FINISHED','FAILED'],[0.15,0.2,0.45,0.2]),enumF('catalog',['hive','iceberg','mysql','postgresql'],[0.3,0.25,0.25,0.2])]);

add('druid-log','druid:log','Apache','Druid','json','Apache Druid query log',
  [F.ts,F.level,F.status,F.duration],
  {},
  [enumF('query_type',['timeseries','topN','groupBy','scan','search'],[0.25,0.2,0.25,0.2,0.1]),intF('num_rows',0,1000000)]);

add('pinot-log','pinot:log','Apache','Pinot','json','Apache Pinot query log',
  [F.ts,F.level,F.status,F.duration],
  {},
  [enumF('query_type',['SELECT','AGGREGATE','GROUP_BY','ORDER_BY'],[0.3,0.25,0.25,0.2]),intF('docs_scanned',0,1000000)]);

// ═══════════════════════════════════════════════════════════════════════════════
// INFRASTRUCTURE — Message Queues
// ═══════════════════════════════════════════════════════════════════════════════
add('activemq-log','activemq:log','Apache','ActiveMQ','json','Apache ActiveMQ log event',
  [F.ts,F.level],
  {},
  [enumF('component',['broker','transport','store','network','advisory'],[0.25,0.2,0.2,0.2,0.15]),F.msg]);

add('nats-log','nats:log','NATS','NATS Server','json','NATS server log event',
  [F.ts,F.level,F.client_ip],
  {src_ip:'client_ip'},
  [enumF('event_type',['connect','disconnect','subscribe','unsubscribe','publish'],[0.2,0.15,0.25,0.15,0.25])]);

add('zeromq-log','zeromq:log','ZeroMQ','ZeroMQ','json','ZeroMQ log event',
  [F.ts,F.level],
  {},
  [enumF('socket_type',['PUB','SUB','REQ','REP','PUSH','PULL'],[0.2,0.2,0.15,0.15,0.15,0.15]),F.msg]);

add('amazonmq-log','amazonmq:log','AWS','Amazon MQ','json','Amazon MQ broker log',
  [F.ts,F.level,F.status,F.region],
  {},
  [enumF('engine',['activemq','rabbitmq'],[0.5,0.5]),F.msg]);

add('redis-streams','redis:streams','Redis','Streams','json','Redis Streams event',
  [F.ts,F.status],
  {},
  [enumF('command',['XADD','XREAD','XREADGROUP','XACK','XDEL'],[0.3,0.25,0.2,0.15,0.1]),intF('stream_length',0,100000)]);

add('celery-log','celery:log','Celery','Task Queue','json','Celery task queue event',
  [F.ts,F.status,F.level],
  {},
  [enumF('task_state',['PENDING','STARTED','SUCCESS','FAILURE','RETRY'],[0.1,0.2,0.4,0.15,0.15]),F.duration]);

// ═══════════════════════════════════════════════════════════════════════════════
// INFRASTRUCTURE — Containers/K8s
// ═══════════════════════════════════════════════════════════════════════════════
add('podman-events','podman:events','Podman','Podman','json','Podman container events',
  [F.ts,F.status],
  {},
  [enumF('event_type',['create','start','stop','die','remove','pull'],[0.15,0.2,0.2,0.15,0.15,0.15]),enumF('container_status',['created','running','paused','exited','dead'],[0.15,0.4,0.1,0.25,0.1])]);

add('containerd-log','containerd:log','containerd','containerd','json','containerd runtime log',
  [F.ts,F.level],
  {},
  [enumF('event_type',['container_create','task_start','task_exit','image_pull','snapshot'],[0.2,0.2,0.2,0.2,0.2]),F.msg]);

add('crio-log','crio:log','CRI-O','CRI-O','json','CRI-O container runtime log',
  [F.ts,F.level],
  {},
  [enumF('event_type',['create','start','stop','remove','pull_image'],[0.2,0.2,0.2,0.2,0.2]),F.msg]);

add('rancher-audit','rancher:audit','Rancher','Rancher','json','Rancher management audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('resource',['cluster','project','namespace','workload','secret'],[0.25,0.2,0.2,0.2,0.15])]);

add('openshift-audit','openshift:audit','Red Hat','OpenShift','json','OpenShift audit log',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('resource',['pods','deployments','routes','builds','imagestreams'],[0.25,0.2,0.2,0.2,0.15])]);

add('nomad-event','nomad:event','HashiCorp','Nomad','json','HashiCorp Nomad event log',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['job_registered','allocation_updated','evaluation_completed','deployment_status','node_event'],[0.2,0.25,0.2,0.2,0.15])]);

add('docker-swarm','docker:swarm','Docker','Swarm','json','Docker Swarm event log',
  [F.ts,F.status],
  {},
  [enumF('event_type',['service_create','service_update','task_start','task_stop','node_join'],[0.2,0.2,0.2,0.2,0.2]),F.hostname]);

add('k3s-log','k3s:log','Rancher','K3s','json','K3s lightweight Kubernetes log',
  [F.ts,F.level,F.hostname],
  {},
  [enumF('component',['kubelet','apiserver','scheduler','controller','etcd'],[0.25,0.2,0.2,0.2,0.15]),F.msg]);

add('microk8s-log','microk8s:log','Canonical','MicroK8s','json','MicroK8s log event',
  [F.ts,F.level,F.hostname],
  {},
  [enumF('service',['kubelet','apiserver','containerd','calico','coredns'],[0.25,0.2,0.2,0.2,0.15]),F.msg]);

add('portainer-audit','portainer:audit','Portainer','Portainer','json','Portainer management audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('resource_type',['container','stack','volume','network','image'],[0.25,0.2,0.2,0.2,0.15])]);

// ═══════════════════════════════════════════════════════════════════════════════
// INFRASTRUCTURE — Config Management
// ═══════════════════════════════════════════════════════════════════════════════
add('saltstack-event','salt:event','SaltStack','Salt','json','SaltStack event log',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('fun',['state.apply','cmd.run','pkg.install','service.restart','grains.items'],[0.25,0.2,0.2,0.2,0.15]),F.user]);

add('pulumi-event','pulumi:event','Pulumi','Pulumi','json','Pulumi IaC event log',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('operation',['create','update','delete','refresh','preview'],[0.2,0.25,0.15,0.2,0.2]),enumF('resource_type',['aws:ec2','aws:s3','azure:vm','gcp:compute'],[0.3,0.25,0.25,0.2])]);

add('cdk-event','cdk:event','AWS','CDK','json','AWS CDK deployment event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('action',['synth','deploy','destroy','diff','bootstrap'],[0.2,0.3,0.15,0.2,0.15]),F.region]);

add('crossplane-event','crossplane:event','Crossplane','Crossplane','json','Crossplane managed resource event',
  [F.ts,F.status],
  {},
  [enumF('resource_type',['rds','s3','vpc','gke','sql'],[0.25,0.2,0.2,0.2,0.15]),enumF('condition',['Synced','Ready','Available','Bound'],[0.3,0.3,0.2,0.2])]);

add('flux-event','flux:event','Flux','GitOps','json','Flux CD GitOps event',
  [F.ts,F.status,F.severity],
  {},
  [enumF('kind',['GitRepository','Kustomization','HelmRelease','HelmChart','ImagePolicy'],[0.2,0.25,0.2,0.2,0.15]),F.msg]);

add('helm-event','helm:event','Helm','Helm','json','Helm chart deployment event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('action',['install','upgrade','rollback','uninstall','test'],[0.25,0.3,0.15,0.15,0.15]),enumF('namespace',['default','kube-system','monitoring','app'],[0.25,0.2,0.25,0.3])]);

add('kustomize-event','kustomize:event','Kubernetes','Kustomize','json','Kustomize build event',
  [F.ts,F.status],
  {},
  [enumF('overlay',['base','dev','staging','production'],[0.2,0.25,0.25,0.3]),F.msg]);

// ═══════════════════════════════════════════════════════════════════════════════
// INFRASTRUCTURE — CI/CD
// ═══════════════════════════════════════════════════════════════════════════════
add('travis-build','travis:build','Travis CI','Travis','json','Travis CI build event',
  [F.ts,F.user,F.status,F.duration],
  {user:'user'},
  [enumF('language',['javascript','python','ruby','java','go'],[0.25,0.2,0.2,0.2,0.15]),enumF('branch',['main','develop','feature','release'],[0.35,0.25,0.25,0.15])]);

add('teamcity-build','teamcity:build','JetBrains','TeamCity','json','TeamCity build event',
  [F.ts,F.user,F.status,F.duration],
  {user:'user'},
  [enumF('build_type',['regular','deployment','composite','personal'],[0.35,0.25,0.2,0.2])]);

add('bamboo-build','bamboo:build','Atlassian','Bamboo','json','Bamboo build event',
  [F.ts,F.user,F.status,F.duration],
  {user:'user'},
  [enumF('plan_type',['build','deployment','branch'],[0.4,0.35,0.25])]);

add('azure-pipelines','azure:pipelines','Microsoft','Azure Pipelines','json','Azure Pipelines build event',
  [F.ts,F.user,F.status,F.duration],
  {user:'user'},
  [enumF('pipeline_type',['build','release','yaml','classic'],[0.3,0.25,0.25,0.2]),F.region]);

add('aws-codepipeline','aws:codepipeline','AWS','CodePipeline','json','AWS CodePipeline execution event',
  [F.ts,F.status,F.duration,F.region],
  {},
  [enumF('stage',['Source','Build','Test','Deploy','Approval'],[0.2,0.2,0.2,0.2,0.2]),F.id]);

add('gcp-cloudbuild','gcp:cloudbuild','Google','Cloud Build','json','GCP Cloud Build event',
  [F.ts,F.status,F.duration,F.region],
  {},
  [enumF('trigger_type',['push','pull_request','manual','schedule'],[0.3,0.25,0.25,0.2]),F.id]);

add('drone-build','drone:build','Drone','Drone CI','json','Drone CI build event',
  [F.ts,F.user,F.status,F.duration],
  {user:'user'},
  [enumF('event',['push','pull_request','tag','promote','cron'],[0.3,0.25,0.15,0.15,0.15])]);

add('woodpecker-build','woodpecker:build','Woodpecker','Woodpecker CI','json','Woodpecker CI build event',
  [F.ts,F.user,F.status,F.duration],
  {user:'user'},
  [enumF('event',['push','pull_request','tag','manual'],[0.35,0.25,0.2,0.2])]);

add('tekton-event','tekton:event','Tekton','Pipelines','json','Tekton pipeline event',
  [F.ts,F.status],
  {},
  [enumF('kind',['PipelineRun','TaskRun','Pipeline','Task'],[0.3,0.3,0.2,0.2]),F.duration]);

add('harness-event','harness:event','Harness','CD','json','Harness deployment event',
  [F.ts,F.user,F.status,F.duration],
  {user:'user'},
  [enumF('deployment_type',['kubernetes','ecs','lambda','ssh','helm'],[0.3,0.2,0.15,0.15,0.2])]);

add('codefresh-event','codefresh:event','Codefresh','CI/CD','json','Codefresh pipeline event',
  [F.ts,F.user,F.status,F.duration],
  {user:'user'},
  [enumF('pipeline_type',['build','deploy','test','promote'],[0.3,0.3,0.2,0.2])]);

// ═══════════════════════════════════════════════════════════════════════════════
// INFRASTRUCTURE — Monitoring
// ═══════════════════════════════════════════════════════════════════════════════
add('icinga-event','icinga:event','Icinga','Icinga2','json','Icinga 2 monitoring event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('check_type',['host','service','cluster','notification'],[0.25,0.35,0.2,0.2]),F.msg]);

add('librenms-event','librenms:event','LibreNMS','LibreNMS','json','LibreNMS monitoring event',
  [F.ts,F.hostname,F.severity],
  {},
  [enumF('alert_type',['device_down','port_down','processor','memory','storage'],[0.2,0.2,0.2,0.2,0.2]),F.msg]);

add('checkmk-event','checkmk:event','Checkmk','Checkmk','json','Checkmk monitoring event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('service_type',['cpu','memory','disk','network','process'],[0.2,0.2,0.2,0.2,0.2])]);

add('prtg-event','prtg:event','Paessler','PRTG','json','PRTG network monitor event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('sensor_type',['ping','snmp','http','bandwidth','cpu'],[0.2,0.2,0.2,0.2,0.2]),intF('value',0,100)]);

add('logicmonitor-event','logicmonitor:event','LogicMonitor','Platform','json','LogicMonitor alert event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('resource_type',['server','network','storage','cloud','container'],[0.2,0.2,0.2,0.2,0.2]),F.msg]);

add('solarwinds-event','solarwinds:event','SolarWinds','Orion','json','SolarWinds Orion alert event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('module',['npm','sam','ncm','ipam','vnqm'],[0.25,0.2,0.2,0.2,0.15]),F.msg]);

add('catchpoint-event','catchpoint:event','Catchpoint','Monitoring','json','Catchpoint monitoring event',
  [F.ts,F.severity,F.status],
  {},
  [enumF('test_type',['web','api','dns','tcp','bgp','smtp'],[0.2,0.2,0.15,0.15,0.15,0.15]),F.duration]);

add('pingdom-event','pingdom:event','SolarWinds','Pingdom','json','Pingdom uptime monitoring event',
  [F.ts,F.severity,F.status],
  {},
  [enumF('check_type',['http','tcp','dns','udp','smtp','pop3','imap'],[0.3,0.15,0.15,0.1,0.1,0.1,0.1]),F.duration]);

add('statuscake-event','statuscake:event','StatusCake','StatusCake','json','StatusCake monitoring event',
  [F.ts,F.severity,F.status],
  {},
  [enumF('test_type',['http','tcp','dns','ssl','pagespeed'],[0.3,0.2,0.2,0.15,0.15]),F.duration]);

add('uptimerobot-event','uptimerobot:event','UptimeRobot','UptimeRobot','json','UptimeRobot monitoring event',
  [F.ts,F.severity,F.status],
  {},
  [enumF('monitor_type',['http','keyword','ping','port','heartbeat'],[0.3,0.2,0.2,0.15,0.15]),F.duration]);

add('betterstack-event','betterstack:event','Better Stack','Uptime','json','Better Stack uptime event',
  [F.ts,F.severity,F.status],
  {},
  [enumF('check_type',['http','tcp','dns','ssl','cron'],[0.3,0.2,0.2,0.15,0.15]),F.duration]);

add('victorops-event','victorops:event','Splunk','VictorOps','json','VictorOps incident event',
  [F.ts,F.user,F.severity,F.status],
  {user:'user'},
  [enumF('message_type',['CRITICAL','WARNING','ACKNOWLEDGEMENT','RECOVERY','INFO'],[0.25,0.2,0.2,0.2,0.15])]);

add('appdynamics-event','appdynamics:event','Cisco','AppDynamics','json','AppDynamics application event',
  [F.ts,F.severity,F.hostname,F.status],
  {},
  [enumF('event_type',['health_rule','policy','error','slow_transaction','node_event'],[0.25,0.2,0.2,0.2,0.15]),F.duration]);

add('instana-event','instana:event','IBM','Instana','json','Instana APM event',
  [F.ts,F.severity,F.hostname,F.status],
  {},
  [enumF('entity_type',['host','process','service','endpoint','call'],[0.2,0.2,0.2,0.2,0.2]),F.duration]);

add('jaeger-span','jaeger:span','Jaeger','Tracing','json','Jaeger distributed trace span',
  [F.ts,F.status,F.duration],
  {},
  [enumF('service',['api-gateway','user-service','order-service','payment-service'],[0.3,0.25,0.25,0.2]),F.id]);

add('zipkin-span','zipkin:span','Zipkin','Tracing','json','Zipkin distributed trace span',
  [F.ts,F.status,F.duration],
  {},
  [enumF('kind',['SERVER','CLIENT','PRODUCER','CONSUMER'],[0.3,0.3,0.2,0.2]),F.id]);

add('signoz-event','signoz:event','SigNoz','Observability','json','SigNoz observability event',
  [F.ts,F.severity,F.status],
  {},
  [enumF('signal_type',['trace','metric','log','exception'],[0.25,0.25,0.25,0.25]),F.duration]);

add('uptrace-span','uptrace:span','Uptrace','Tracing','json','Uptrace distributed trace span',
  [F.ts,F.status,F.duration],
  {},
  [enumF('system',['http','db','messaging','rpc'],[0.3,0.25,0.25,0.2]),F.id]);

add('groundcover-event','groundcover:event','Groundcover','eBPF','json','Groundcover eBPF observability event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('protocol',['http','grpc','redis','postgresql','mysql'],[0.25,0.2,0.2,0.2,0.15]),F.duration]);

// ═══════════════════════════════════════════════════════════════════════════════
// INFRASTRUCTURE — DNS
// ═══════════════════════════════════════════════════════════════════════════════
add('bluecat-dns','bluecat:dns','BlueCat','DNS','json','BlueCat DNS query log',
  [F.ts,F.client_ip],
  {src_ip:'client_ip'},
  [enumF('query_type',['A','AAAA','CNAME','MX','TXT','PTR'],[0.3,0.15,0.15,0.1,0.15,0.15]),enumF('response_code',['NOERROR','NXDOMAIN','SERVFAIL','REFUSED'],[0.7,0.15,0.1,0.05])]);

add('efficientip-dns','efficientip:dns','EfficientIP','SOLIDserver','json','EfficientIP DNS query log',
  [F.ts,F.client_ip],
  {src_ip:'client_ip'},
  [enumF('query_type',['A','AAAA','CNAME','MX','TXT'],[0.35,0.15,0.2,0.15,0.15]),enumF('rcode',['NOERROR','NXDOMAIN','SERVFAIL'],[0.7,0.2,0.1])]);

add('powerdns-log','powerdns:log','PowerDNS','Recursor','json','PowerDNS query log',
  [F.ts,F.client_ip],
  {src_ip:'client_ip'},
  [enumF('query_type',['A','AAAA','CNAME','NS','SOA','MX'],[0.3,0.15,0.15,0.15,0.1,0.15]),enumF('rcode',['NoError','NXDomain','ServFail','Refused'],[0.7,0.15,0.1,0.05])]);

add('coredns-log','coredns:log','CoreDNS','CoreDNS','json','CoreDNS query log',
  [F.ts,F.client_ip],
  {src_ip:'client_ip'},
  [enumF('qtype',['A','AAAA','SRV','CNAME','TXT'],[0.3,0.15,0.2,0.2,0.15]),enumF('rcode',['NOERROR','NXDOMAIN','SERVFAIL'],[0.75,0.15,0.1])]);

add('unbound-dns','unbound:dns','NLnet Labs','Unbound','syslog','Unbound DNS resolver log',
  [F.ts,F.client_ip],
  {src_ip:'client_ip'},
  [enumF('query_type',['A','AAAA','CNAME','MX','TXT'],[0.35,0.15,0.2,0.15,0.15]),enumF('rcode',['NOERROR','NXDOMAIN','SERVFAIL'],[0.7,0.2,0.1])]);

add('bind-detailed','bind:query','ISC','BIND','syslog','BIND DNS detailed query log',
  [F.ts,F.client_ip],
  {src_ip:'client_ip'},
  [enumF('query_class',['IN','CH','HS','ANY'],[0.85,0.05,0.05,0.05]),enumF('query_type',['A','AAAA','MX','NS','SOA','TXT'],[0.3,0.15,0.15,0.15,0.1,0.15])]);

add('pihole-log','pihole:query','Pi-hole','Pi-hole','json','Pi-hole DNS query log',
  [F.ts,F.client_ip],
  {src_ip:'client_ip'},
  [enumF('status',['allowed','blocked','cached','forwarded'],[0.4,0.2,0.25,0.15]),enumF('query_type',['A','AAAA','PTR','SRV'],[0.4,0.25,0.2,0.15])]);

add('adguard-dns','adguard:dns','AdGuard','Home','json','AdGuard Home DNS query log',
  [F.ts,F.client_ip],
  {src_ip:'client_ip'},
  [enumF('filter_result',['allowed','blocked_safebrowsing','blocked_parental','blocked_filter'],[0.5,0.15,0.15,0.2]),enumF('qtype',['A','AAAA','HTTPS','CNAME'],[0.4,0.25,0.2,0.15])]);

add('cloudflare-dns','cloudflare:dns','Cloudflare','DNS','json','Cloudflare DNS analytics log',
  [F.ts,F.client_ip],
  {src_ip:'client_ip'},
  [enumF('query_type',['A','AAAA','CNAME','MX','TXT','HTTPS'],[0.3,0.15,0.15,0.1,0.15,0.15]),enumF('response_code',['NOERROR','NXDOMAIN','SERVFAIL'],[0.75,0.15,0.1])]);

add('route53-resolver','aws:route53:resolver','AWS','Route 53 Resolver','json','AWS Route 53 Resolver query log',
  [F.ts,F.client_ip,F.region],
  {src_ip:'client_ip'},
  [enumF('query_type',['A','AAAA','CNAME','MX','TXT'],[0.35,0.15,0.2,0.15,0.15]),enumF('rcode',['NOERROR','NXDOMAIN','SERVFAIL'],[0.7,0.2,0.1])]);

add('menmice-dns','menmice:dns','Men&Mice','Micetro','json','Men&Mice Micetro DNS audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('object_type',['zone','record','range','scope'],[0.3,0.3,0.2,0.2])]);

// ═══════════════════════════════════════════════════════════════════════════════
// INFRASTRUCTURE — DHCP
// ═══════════════════════════════════════════════════════════════════════════════
add('isc-dhcp','isc:dhcp','ISC','DHCP','syslog','ISC DHCP server log',
  [F.ts,F.client_ip,F.hostname],
  {src_ip:'client_ip'},
  [enumF('msg_type',['DHCPDISCOVER','DHCPOFFER','DHCPREQUEST','DHCPACK','DHCPNAK','DHCPRELEASE'],[0.15,0.15,0.2,0.25,0.05,0.2])]);

add('kea-dhcp','kea:dhcp','ISC','Kea','json','ISC Kea DHCP server log',
  [F.ts,F.client_ip,F.hostname],
  {src_ip:'client_ip'},
  [enumF('msg_type',['DHCPDISCOVER','DHCPOFFER','DHCPREQUEST','DHCPACK','DHCPNAK'],[0.2,0.2,0.2,0.25,0.15]),enumF('subnet',['10.0.0.0/24','10.0.1.0/24','192.168.0.0/24'],[0.4,0.35,0.25])]);

add('windows-dhcp','windows:dhcp','Microsoft','DHCP','json','Windows DHCP server log',
  [F.ts,F.client_ip,F.hostname],
  {src_ip:'client_ip'},
  [enumF('event_id',['10','11','12','13','15','17'],[0.2,0.15,0.2,0.2,0.15,0.1]),enumF('scope',['10.0.0.0','10.0.1.0','192.168.1.0'],[0.4,0.35,0.25])]);

add('infoblox-dhcp','infoblox:dhcp','Infoblox','NIOS','json','Infoblox DHCP server log',
  [F.ts,F.client_ip,F.hostname],
  {src_ip:'client_ip'},
  [enumF('msg_type',['DHCPDISCOVER','DHCPOFFER','DHCPREQUEST','DHCPACK','DHCPRELEASE'],[0.2,0.2,0.2,0.25,0.15]),enumF('network_view',['default','internal','guest'],[0.5,0.3,0.2])]);

add('bluecat-dhcp','bluecat:dhcp','BlueCat','DHCP','json','BlueCat DHCP server log',
  [F.ts,F.client_ip,F.hostname],
  {src_ip:'client_ip'},
  [enumF('msg_type',['DISCOVER','OFFER','REQUEST','ACK','NAK','RELEASE'],[0.15,0.15,0.2,0.25,0.05,0.2])]);

// ═══════════════════════════════════════════════════════════════════════════════
// INFRASTRUCTURE — RADIUS/TACACS
// ═══════════════════════════════════════════════════════════════════════════════
add('freeradius-log','freeradius:log','FreeRADIUS','FreeRADIUS','json','FreeRADIUS authentication log',
  [F.ts,F.user,F.client_ip,F.status],
  {src_ip:'client_ip',user:'user'},
  [enumF('packet_type',['Access-Request','Access-Accept','Access-Reject','Accounting-Request'],[0.3,0.3,0.15,0.25]),enumF('auth_type',['PAP','CHAP','EAP-TLS','PEAP'],[0.25,0.2,0.3,0.25])]);

add('cisco-tacacs','cisco:tacacs','Cisco','TACACS+','syslog','Cisco TACACS+ authentication log',
  [F.ts,F.user,F.client_ip,F.status],
  {src_ip:'client_ip',user:'user'},
  [enumF('service',['shell','enable','system','ppp'],[0.4,0.25,0.2,0.15]),enumF('priv_level',['0','1','5','15'],[0.2,0.3,0.2,0.3])]);

add('clearpass-auth','clearpass:auth','Aruba','ClearPass','json','Aruba ClearPass authentication log',
  [F.ts,F.user,F.client_ip,F.status],
  {src_ip:'client_ip',user:'user'},
  [enumF('auth_source',['local','ad','ldap','radius'],[0.2,0.35,0.2,0.25]),enumF('service',['802.1X','guest','onboarding','posture'],[0.35,0.25,0.2,0.2])]);

add('radiator-log','radiator:log','Radiator','RADIUS','json','Radiator RADIUS server log',
  [F.ts,F.user,F.client_ip,F.status],
  {src_ip:'client_ip',user:'user'},
  [enumF('packet_type',['Access-Request','Access-Accept','Access-Reject','Accounting'],[0.3,0.3,0.15,0.25])]);

add('nps-log','nps:log','Microsoft','NPS','json','Windows NPS RADIUS log',
  [F.ts,F.user,F.client_ip,F.status],
  {src_ip:'client_ip',user:'user'},
  [enumF('reason_code',['0','2','6','16','23'],[0.4,0.2,0.15,0.15,0.1]),enumF('auth_type',['PEAP','EAP-TLS','PAP','MS-CHAPv2'],[0.3,0.25,0.2,0.25])]);

// ═══════════════════════════════════════════════════════════════════════════════
// INFRASTRUCTURE — Backup
// ═══════════════════════════════════════════════════════════════════════════════
add('acronis-event','acronis:event','Acronis','Backup','json','Acronis backup event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('operation',['backup','restore','replicate','validate','cleanup'],[0.35,0.2,0.15,0.15,0.15]),F.duration]);

add('cohesity-event','cohesity:event','Cohesity','DataProtect','json','Cohesity backup event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('job_type',['backup','restore','clone','replicate','archive'],[0.3,0.2,0.15,0.2,0.15]),F.duration]);

add('nakivo-event','nakivo:event','NAKIVO','Backup','json','NAKIVO backup event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('job_type',['backup','replication','recovery','verification'],[0.35,0.25,0.2,0.2]),F.duration]);

add('zerto-event','zerto:event','Zerto','DR','json','Zerto disaster recovery event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('event_type',['replication','failover','failback','test_failover','move'],[0.35,0.2,0.15,0.15,0.15]),F.severity]);

add('druva-event','druva:event','Druva','Cloud Backup','json','Druva cloud backup event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('source_type',['endpoint','nas','vm','saas','database'],[0.2,0.2,0.2,0.2,0.2]),F.duration]);

add('msp360-event','msp360:event','MSP360','Backup','json','MSP360 backup event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('plan_type',['file_backup','image_backup','sql_backup','exchange_backup'],[0.3,0.25,0.25,0.2]),F.duration]);

add('carbonite-event','carbonite:event','Carbonite','Backup','json','Carbonite backup event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('backup_type',['file','image','sql','vm'],[0.35,0.25,0.2,0.2]),F.duration]);

add('datto-event','datto:event','Datto','SIRIS','json','Datto SIRIS backup event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('event_type',['backup','screenshot_verify','offsite','restore','boot_check'],[0.3,0.2,0.2,0.15,0.15])]);

add('arcserve-event','arcserve:event','Arcserve','UDP','json','Arcserve UDP backup event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('job_type',['backup','restore','replicate','virtual_standby'],[0.35,0.25,0.2,0.2]),F.duration]);

add('bacula-event','bacula:event','Bacula','Enterprise','json','Bacula backup event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('job_type',['Backup','Restore','Verify','Admin','Copy','Migrate'],[0.35,0.2,0.15,0.1,0.1,0.1]),F.level]);

// ═══════════════════════════════════════════════════════════════════════════════
// INFRASTRUCTURE — Printing/Document
// ═══════════════════════════════════════════════════════════════════════════════
add('cups-log','cups:log','Apple','CUPS','syslog','CUPS print server log',
  [F.ts,F.user,F.hostname,F.status],
  {user:'user'},
  [enumF('operation',['Print-Job','Cancel-Job','Get-Jobs','Get-Printer-Attributes'],[0.4,0.15,0.25,0.2]),intF('pages',1,100)]);

add('papercut-log','papercut:log','PaperCut','MF','json','PaperCut print management log',
  [F.ts,F.user,F.hostname,F.status],
  {user:'user'},
  [enumF('document_type',['document','spreadsheet','presentation','image','pdf'],[0.25,0.2,0.15,0.15,0.25]),intF('pages',1,200),enumF('color',['grayscale','color'],[0.6,0.4])]);

add('pharos-log','pharos:log','Pharos','Blueprint','json','Pharos print management log',
  [F.ts,F.user,F.hostname,F.status],
  {user:'user'},
  [enumF('job_status',['printed','released','deleted','held'],[0.5,0.2,0.15,0.15]),intF('pages',1,100)]);

add('equitrac-log','equitrac:log','Equitrac','Office','json','Equitrac print management log',
  [F.ts,F.user,F.hostname,F.status],
  {user:'user'},
  [enumF('device_type',['printer','copier','mfp','fax'],[0.35,0.25,0.25,0.15]),intF('pages',1,100)]);

add('printerlogic-log','printerlogic:log','PrinterLogic','SaaS','json','PrinterLogic management log',
  [F.ts,F.user,F.hostname,F.status],
  {user:'user'},
  [enumF('event_type',['print_job','driver_install','printer_deploy','self_service'],[0.4,0.2,0.2,0.2])]);

// ═══════════════════════════════════════════════════════════════════════════════
// INFRASTRUCTURE — Endpoint Management
// ═══════════════════════════════════════════════════════════════════════════════
add('sccm-event','sccm:event','Microsoft','MECM','json','SCCM/MECM management event',
  [F.ts,F.hostname,F.status,F.user],
  {user:'user'},
  [enumF('feature',['software_update','application','compliance','inventory','os_deployment'],[0.25,0.2,0.2,0.2,0.15])]);

add('intune-event','intune:event','Microsoft','Intune','json','Microsoft Intune management event',
  [F.ts,F.hostname,F.user,F.status],
  {user:'user'},
  [enumF('category',['enrollment','compliance','configuration','app_management','device_action'],[0.2,0.2,0.2,0.2,0.2]),F.os]);

add('workspaceone-event','workspaceone:event','VMware','Workspace ONE','json','VMware Workspace ONE UEM event',
  [F.ts,F.hostname,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['enrollment','compliance','profile','app_install','command'],[0.2,0.2,0.2,0.2,0.2]),F.os]);

add('bigfix-event','bigfix:event','HCL','BigFix','json','HCL BigFix endpoint management event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('action_type',['patch','software','compliance','policy','inventory'],[0.25,0.2,0.2,0.2,0.15]),F.os]);

add('ivanti-event','ivanti:event','Ivanti','Neurons','json','Ivanti Neurons endpoint event',
  [F.ts,F.hostname,F.user,F.status],
  {user:'user'},
  [enumF('module',['patch','security','discovery','automation','service_management'],[0.25,0.2,0.2,0.2,0.15])]);

add('ninjarmm-event','ninjarmm:event','NinjaRMM','NinjaOne','json','NinjaOne RMM event',
  [F.ts,F.hostname,F.user,F.status],
  {user:'user'},
  [enumF('activity_type',['patch','script','alert','ticket','backup'],[0.25,0.2,0.2,0.2,0.15]),F.os]);

add('connectwise-event','connectwise:event','ConnectWise','Automate','json','ConnectWise Automate event',
  [F.ts,F.hostname,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['script','monitor','patch','ticket','remote_session'],[0.2,0.2,0.2,0.2,0.2])]);

add('datto-rmm-event','datto:rmm','Datto','RMM','json','Datto RMM management event',
  [F.ts,F.hostname,F.user,F.status],
  {user:'user'},
  [enumF('component',['monitoring','patching','scripting','remote_access'],[0.3,0.25,0.25,0.2])]);

add('kandji-event','kandji:event','Kandji','MDM','json','Kandji Apple MDM event',
  [F.ts,F.hostname,F.user,F.status],
  {user:'user'},
  [enumF('blueprint',['standard','executive','developer','kiosk'],[0.35,0.2,0.25,0.2])]);

add('mosyle-event','mosyle:event','Mosyle','MDM','json','Mosyle Apple MDM event',
  [F.ts,F.hostname,F.user,F.status],
  {user:'user'},
  [enumF('action',['enroll','push_profile','install_app','lock','wipe'],[0.2,0.25,0.25,0.15,0.15])]);

add('addigy-event','addigy:event','Addigy','MDM','json','Addigy Apple MDM event',
  [F.ts,F.hostname,F.user,F.status],
  {user:'user'},
  [enumF('policy_type',['software','restriction','configuration','compliance'],[0.3,0.25,0.25,0.2])]);

add('fleet-event','fleet:event','Fleet','osquery','json','Fleet osquery management event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('activity_type',['query','policy','vulnerability','host_enrolled','host_deleted'],[0.25,0.2,0.2,0.2,0.15]),F.os]);

add('kolide-event','kolide:event','Kolide','K2','json','Kolide endpoint security event',
  [F.ts,F.hostname,F.user,F.status],
  {user:'user'},
  [enumF('check_type',['device_health','compliance','vulnerability','configuration'],[0.3,0.25,0.25,0.2]),F.os]);

// ═══════════════════════════════════════════════════════════════════════════════
// INFRASTRUCTURE — Network Management
// ═══════════════════════════════════════════════════════════════════════════════
add('solarwinds-npm','solarwinds:npm','SolarWinds','NPM','json','SolarWinds NPM network event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('alert_type',['node_down','interface_down','high_cpu','high_memory','high_response_time'],[0.2,0.2,0.2,0.2,0.2]),intF('response_time_ms',1,5000)]);

add('auvik-event','auvik:event','Auvik','Network Management','json','Auvik network management event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('alert_type',['device_offline','config_change','new_device','bandwidth','interface_error'],[0.2,0.2,0.2,0.2,0.2])]);

add('domotz-event','domotz:event','Domotz','Network Monitor','json','Domotz network monitoring event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('event_type',['device_online','device_offline','port_change','ip_change','new_device'],[0.2,0.2,0.2,0.2,0.2])]);

add('netbox-audit','netbox:audit','NetBox','DCIM','json','NetBox DCIM audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('object_type',['device','interface','ip_address','circuit','rack','site'],[0.2,0.15,0.2,0.15,0.15,0.15])]);

add('phpipam-audit','phpipam:audit','phpIPAM','IPAM','json','phpIPAM IP address management audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('object_type',['subnet','address','vlan','vrf','device'],[0.25,0.25,0.2,0.15,0.15])]);

add('opennms-event','opennms:event','OpenNMS','Horizon','json','OpenNMS network monitoring event',
  [F.ts,F.hostname,F.severity],
  {},
  [enumF('event_type',['node_down','interface_down','service_down','threshold','trap'],[0.2,0.2,0.2,0.2,0.2]),F.msg]);

add('manageengine-opm','manageengine:opm','ManageEngine','OpManager','json','ManageEngine OpManager event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('monitor_type',['availability','performance','interface','syslog','trap'],[0.2,0.2,0.2,0.2,0.2]),F.msg]);

add('whatsupgold-event','whatsupgold:event','Progress','WhatsUp Gold','json','WhatsUp Gold network monitoring event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('monitor',['ping','tcp','http','snmp','wmi'],[0.25,0.2,0.2,0.2,0.15]),intF('response_time_ms',1,5000)]);

add('observium-event','observium:event','Observium','Network Monitor','json','Observium network monitoring event',
  [F.ts,F.hostname,F.severity],
  {},
  [enumF('entity_type',['device','port','sensor','processor','storage'],[0.2,0.2,0.2,0.2,0.2]),F.msg]);

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH 2 — Additional sourcetypes to reach 1000+
// ═══════════════════════════════════════════════════════════════════════════════

// ── Healthcare / Medical ─────────────────────────────────────────────────────
add('epic-audit','epic:audit','Epic','EHR','json','Epic EHR audit log',
  [F.ts,F.user,F.action,F.status,F.src_ip],
  {src_ip:'src_ip',user:'user'},
  [enumF('department',['emergency','radiology','pharmacy','lab','cardiology'],[0.2,0.2,0.2,0.2,0.2])]);

add('cerner-audit','cerner:audit','Cerner','Millennium','json','Cerner Millennium audit log',
  [F.ts,F.user,F.action,F.status,F.src_ip],
  {src_ip:'src_ip',user:'user'},
  [enumF('resource',['patient','order','result','document','medication'],[0.2,0.2,0.2,0.2,0.2])]);

add('meditech-audit','meditech:audit','MEDITECH','Expanse','json','MEDITECH audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('module',['clinical','financial','admin','pharmacy','lab'],[0.2,0.2,0.2,0.2,0.2])]);

add('allscripts-audit','allscripts:audit','Allscripts','Sunrise','json','Allscripts EHR audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('access_type',['view','edit','print','export','delete'],[0.3,0.25,0.2,0.15,0.1])]);

add('athenahealth-audit','athenahealth:audit','athenahealth','athenaOne','json','athenahealth audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('service',['clinical','revenue_cycle','patient_engagement','practice_mgmt'],[0.3,0.25,0.25,0.2])]);

add('philips-medical','philips:medical','Philips','HealthSuite','json','Philips medical device log',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('device_type',['monitor','ventilator','imaging','infusion'],[0.3,0.25,0.25,0.2])]);

add('ge-healthcare','ge:healthcare','GE','HealthCare','json','GE HealthCare device log',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('modality',['ct','mri','xray','ultrasound','mammography'],[0.2,0.2,0.2,0.2,0.2])]);

add('dicom-log','dicom:log','DICOM','PACS','json','DICOM PACS audit log',
  [F.ts,F.user,F.src_ip,F.action],
  {src_ip:'src_ip',user:'user'},
  [enumF('service',['C-STORE','C-FIND','C-MOVE','C-GET','C-ECHO'],[0.3,0.2,0.2,0.15,0.15])]);

add('hl7-message','hl7:message','HL7','FHIR','json','HL7 FHIR message log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('resource_type',['Patient','Observation','Medication','Encounter','Condition'],[0.2,0.2,0.2,0.2,0.2])]);

add('imprivata-audit','imprivata:audit','Imprivata','OneSign','json','Imprivata OneSign SSO audit',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('auth_method',['proximity','fingerprint','password','badge','iris'],[0.2,0.2,0.2,0.2,0.2])]);

// ── Financial / Banking ──────────────────────────────────────────────────────
add('swift-message','swift:message','SWIFT','Alliance','json','SWIFT financial message log',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('msg_type',['MT103','MT202','MT940','MT950','MT199'],[0.3,0.2,0.2,0.15,0.15]),F.id]);

add('fis-audit','fis:audit','FIS','Banking','json','FIS banking platform audit log',
  [F.ts,F.user,F.action,F.status,F.src_ip],
  {src_ip:'src_ip',user:'user'},
  [enumF('module',['core_banking','payments','lending','treasury'],[0.3,0.25,0.25,0.2])]);

add('temenos-audit','temenos:audit','Temenos','T24','json','Temenos T24 audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('application',['customer','account','funds_transfer','loan','deposit'],[0.2,0.2,0.2,0.2,0.2])]);

add('finastra-audit','finastra:audit','Finastra','Fusion','json','Finastra Fusion audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('product',['payments','lending','treasury','trade_finance'],[0.3,0.25,0.25,0.2])]);

add('plaid-event','plaid:event','Plaid','API','json','Plaid API event log',
  [F.ts,F.status,F.client_ip],
  {src_ip:'client_ip'},
  [enumF('endpoint',['auth','transactions','balance','identity','investments'],[0.2,0.25,0.2,0.2,0.15]),F.duration]);

// ── Retail / POS ─────────────────────────────────────────────────────────────
add('verifone-pos','verifone:pos','Verifone','POS','json','Verifone POS terminal log',
  [F.ts,F.status],
  {},
  [enumF('transaction_type',['sale','refund','void','auth','capture'],[0.4,0.15,0.1,0.2,0.15]),intF('amount_cents',100,50000)]);

add('ingenico-pos','ingenico:pos','Ingenico','POS','json','Ingenico POS terminal log',
  [F.ts,F.status],
  {},
  [enumF('card_type',['visa','mastercard','amex','discover','debit'],[0.3,0.25,0.15,0.1,0.2]),enumF('entry_mode',['chip','contactless','swipe','manual'],[0.35,0.3,0.2,0.15])]);

add('lightspeed-pos','lightspeed:event','Lightspeed','POS','json','Lightspeed POS event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['sale','refund','inventory_update','customer_created','discount_applied'],[0.3,0.15,0.2,0.2,0.15])]);

add('toast-pos','toast:event','Toast','POS','json','Toast restaurant POS event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('order_type',['dine_in','takeout','delivery','catering'],[0.35,0.25,0.25,0.15])]);

add('clover-pos','clover:event','Clover','POS','json','Clover POS event log',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['payment','refund','order','inventory','employee_clock'],[0.3,0.15,0.2,0.2,0.15])]);

// ── Telecom / ISP ────────────────────────────────────────────────────────────
add('nokia-nsp','nokia:nsp','Nokia','NSP','json','Nokia NSP network event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('alarm_type',['equipment','communication','processing','environmental','qos'],[0.2,0.25,0.2,0.15,0.2])]);

add('ericsson-enm','ericsson:enm','Ericsson','ENM','json','Ericsson ENM network event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('event_type',['alarm','performance','configuration','fault','security'],[0.25,0.2,0.2,0.2,0.15])]);

add('huawei-nce','huawei:nce','Huawei','NCE','json','Huawei NCE network event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('service_type',['ip','optical','microwave','sdwan'],[0.3,0.25,0.25,0.2])]);

add('ciena-event','ciena:event','Ciena','Blue Planet','json','Ciena Blue Planet event log',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('resource',['port','channel','path','node','link'],[0.2,0.2,0.2,0.2,0.2])]);

add('calix-event','calix:event','Calix','AXOS','json','Calix AXOS event log',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('module',['ont','olt','subscriber','service','network'],[0.2,0.2,0.2,0.2,0.2])]);

add('adtran-event','adtran:event','Adtran','Mosaic','json','Adtran Mosaic event log',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('feature',['subscriber','network','service','security'],[0.3,0.25,0.25,0.2])]);

add('ribbon-sbc','ribbon:sbc','Ribbon','SBC','json','Ribbon SBC call event',
  [F.ts,F.src_ip,F.dst_ip,F.status],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('sip_method',['INVITE','BYE','REGISTER','OPTIONS','CANCEL'],[0.3,0.2,0.2,0.15,0.15]),F.duration]);

add('audiocodes-sbc','audiocodes:sbc','AudioCodes','Mediant','json','AudioCodes SBC event log',
  [F.ts,F.src_ip,F.dst_ip,F.status],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('call_type',['inbound','outbound','transit','emergency'],[0.3,0.3,0.25,0.15]),F.duration]);

add('genesys-event','genesys:event','Genesys','Cloud CX','json','Genesys Cloud contact center event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('media_type',['voice','chat','email','callback','message'],[0.3,0.2,0.2,0.15,0.15]),F.duration]);

add('avaya-event','avaya:event','Avaya','OneCloud','json','Avaya communication event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['call','conference','transfer','hold','voicemail'],[0.3,0.2,0.2,0.15,0.15]),F.duration]);

add('cisco-cucm','cisco:cucm','Cisco','CUCM','json','Cisco Unified Communications event',
  [F.ts,F.user,F.src_ip,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('event_type',['call_started','call_ended','registration','hunt_group','voicemail'],[0.25,0.2,0.2,0.2,0.15]),F.duration]);

add('mitel-event','mitel:event','Mitel','MiVoice','json','Mitel MiVoice communication event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('call_type',['internal','external','conference','transfer'],[0.3,0.3,0.2,0.2]),F.duration]);

// ── Industrial / SCADA / OT (expanding beyond existing) ─────────────────────
add('siemens-plc','siemens:plc','Siemens','SIMATIC','json','Siemens SIMATIC PLC event log',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('event_type',['alarm','diagnostic','process','program_change','cpu_state'],[0.25,0.2,0.2,0.2,0.15])]);

add('allen-bradley-plc','ab:plc','Rockwell','Allen-Bradley','json','Allen-Bradley PLC event log',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('fault_type',['major','minor','io','communication','program'],[0.15,0.25,0.2,0.2,0.2])]);

add('schneider-scada','schneider:scada','Schneider Electric','EcoStruxure','json','Schneider Electric SCADA event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('subsystem',['power','automation','building','it_infrastructure'],[0.3,0.25,0.25,0.2])]);

add('honeywell-dcs','honeywell:dcs','Honeywell','Experion','json','Honeywell Experion DCS event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('point_type',['analog_input','analog_output','digital_input','digital_output'],[0.3,0.2,0.3,0.2])]);

add('abb-scada','abb:scada','ABB','Ability','json','ABB Ability SCADA event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('signal_type',['measurement','alarm','event','command','trip'],[0.2,0.25,0.2,0.2,0.15])]);

add('emerson-dcs','emerson:dcs','Emerson','DeltaV','json','Emerson DeltaV DCS event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('module_type',['controller','io_card','fieldbus','workstation','historian'],[0.25,0.2,0.2,0.2,0.15])]);

add('yokogawa-dcs','yokogawa:dcs','Yokogawa','CENTUM','json','Yokogawa CENTUM DCS event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('alarm_priority',['emergency','high','medium','low','journal'],[0.1,0.2,0.3,0.25,0.15])]);

add('wonderware-scada','wonderware:event','AVEVA','Wonderware','json','Wonderware SCADA historian event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('tag_type',['analog','discrete','string','complex'],[0.35,0.3,0.2,0.15]),intF('value',0,1000)]);

add('ignition-scada','ignition:event','Inductive','Ignition','json','Ignition SCADA event log',
  [F.ts,F.user,F.hostname,F.status],
  {user:'user'},
  [enumF('event_type',['tag_change','alarm','script','query','audit'],[0.2,0.25,0.2,0.15,0.2])]);

add('claroty-alert','claroty:alert','Claroty','xDome','json','Claroty OT security alert',
  [F.ts,F.src_ip,F.dst_ip,F.severity],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('category',['network_anomaly','vulnerability','policy_violation','baseline_deviation'],[0.25,0.25,0.25,0.25]),F.risk]);

add('nozomi-alert','nozomi:alert','Nozomi Networks','Guardian','json','Nozomi Guardian OT security alert',
  [F.ts,F.src_ip,F.dst_ip,F.severity],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('type',['protocol_anomaly','new_asset','vulnerability','malware','policy'],[0.2,0.2,0.2,0.2,0.2])]);

add('dragos-alert','dragos:alert','Dragos','Platform','json','Dragos ICS security alert',
  [F.ts,F.src_ip,F.severity],
  {src_ip:'src_ip'},
  [enumF('threat_group',['CHERNOVITE','ELECTRUM','XENOTIME','KAMACITE','ERYTHRITE'],[0.2,0.2,0.2,0.2,0.2]),F.risk]);

add('forescout-event','forescout:event','Forescout','eyeSight','json','Forescout device visibility event',
  [F.ts,F.src_ip,F.hostname,F.status],
  {src_ip:'src_ip'},
  [enumF('device_type',['managed','unmanaged','iot','ot','byod'],[0.2,0.2,0.2,0.2,0.2]),F.severity]);

add('armis-event','armis:event','Armis','Platform','json','Armis asset intelligence event',
  [F.ts,F.src_ip,F.severity],
  {src_ip:'src_ip'},
  [enumF('device_type',['it','ot','iot','medical','virtual'],[0.2,0.2,0.2,0.2,0.2]),F.risk]);

// ── Education ────────────────────────────────────────────────────────────────
add('canvas-audit','canvas:audit','Instructure','Canvas','json','Canvas LMS audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('resource',['course','assignment','quiz','discussion','grade'],[0.2,0.2,0.2,0.2,0.2])]);

add('blackboard-audit','blackboard:audit','Anthology','Blackboard','json','Blackboard LMS audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('module',['content','assessment','gradebook','collaboration','admin'],[0.2,0.2,0.2,0.2,0.2])]);

add('moodle-audit','moodle:audit','Moodle','LMS','json','Moodle LMS event log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('component',['course','mod_quiz','mod_assign','mod_forum','core'],[0.2,0.2,0.2,0.2,0.2])]);

add('brightspace-audit','brightspace:audit','D2L','Brightspace','json','D2L Brightspace audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('area',['content','quiz','grades','discussions','admin'],[0.2,0.2,0.2,0.2,0.2])]);

add('clever-event','clever:event','Clever','SSO','json','Clever education SSO event',
  [F.ts,F.user,F.src_ip,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('app',['google_classroom','canvas','khan_academy','ixl','clever_portal'],[0.2,0.2,0.2,0.2,0.2])]);

// ── Government / Compliance ──────────────────────────────────────────────────
add('fedramp-audit','fedramp:audit','FedRAMP','Compliance','json','FedRAMP compliance audit event',
  [F.ts,F.user,F.action,F.status,F.severity],
  {user:'user'},
  [enumF('control_family',['access_control','audit','config_mgmt','identification','risk_assessment'],[0.2,0.2,0.2,0.2,0.2])]);

add('nist-csf-event','nist:csf','NIST','CSF','json','NIST CSF compliance event',
  [F.ts,F.severity,F.status],
  {},
  [enumF('function',['identify','protect','detect','respond','recover'],[0.2,0.2,0.2,0.2,0.2]),enumF('tier',['partial','risk_informed','repeatable','adaptive'],[0.15,0.3,0.35,0.2])]);

add('sox-audit','sox:audit','SOX','Compliance','json','SOX compliance audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('control',['access_review','change_management','segregation_of_duties','financial_close','data_integrity'],[0.2,0.2,0.2,0.2,0.2])]);

add('hipaa-audit','hipaa:audit','HIPAA','Compliance','json','HIPAA compliance audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('safeguard',['access_control','audit_control','integrity','authentication','encryption'],[0.2,0.2,0.2,0.2,0.2])]);

add('pci-dss-event','pci:dss','PCI','DSS','json','PCI DSS compliance event',
  [F.ts,F.user,F.action,F.status,F.severity],
  {user:'user'},
  [enumF('requirement',['firewall','default_passwords','cardholder_data','encryption','antivirus','secure_systems'],[0.15,0.15,0.2,0.2,0.15,0.15])]);

add('gdpr-event','gdpr:event','GDPR','Compliance','json','GDPR data privacy event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('activity',['consent','access_request','erasure','portability','breach_notification'],[0.2,0.2,0.2,0.2,0.2])]);

// ── Physical Security / Access ───────────────────────────────────────────────
add('hikvision-event','hikvision:event','Hikvision','DVR/NVR','json','Hikvision surveillance event',
  [F.ts,F.hostname,F.severity],
  {},
  [enumF('event_type',['motion_detect','line_crossing','intrusion','face_detect','loitering'],[0.25,0.2,0.2,0.2,0.15])]);

add('dahua-event','dahua:event','Dahua','DVR/NVR','json','Dahua surveillance event',
  [F.ts,F.hostname,F.severity],
  {},
  [enumF('alarm_type',['motion','tripwire','intrusion','abandoned_object','missing_object'],[0.3,0.2,0.2,0.15,0.15])]);

add('axis-camera','axis:camera','Axis','Camera','json','Axis network camera event',
  [F.ts,F.hostname,F.severity],
  {},
  [enumF('event_type',['motion','tampering','audio','cross_line','pir'],[0.3,0.2,0.2,0.15,0.15])]);

add('milestone-vms','milestone:event','Milestone','XProtect','json','Milestone XProtect VMS event',
  [F.ts,F.user,F.hostname,F.severity],
  {user:'user'},
  [enumF('event_type',['motion','recording','archive','user_login','system'],[0.25,0.2,0.2,0.2,0.15])]);

add('honeywell-access','honeywell:access','Honeywell','ProWatch','json','Honeywell ProWatch access control event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['card_read','door_forced','door_held','alarm','request_to_exit'],[0.35,0.15,0.15,0.15,0.2])]);

add('hid-access','hid:access','HID Global','Aero','json','HID Global access control event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('credential_type',['card','mobile','biometric','pin','fob'],[0.3,0.2,0.2,0.15,0.15])]);

add('brivo-access','brivo:event','Brivo','Access Control','json','Brivo cloud access control event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['access_granted','access_denied','door_held','door_forced','lockdown'],[0.4,0.2,0.15,0.1,0.15])]);

add('openpath-access','openpath:event','Openpath','Access','json','Openpath access control event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('unlock_method',['app','wave','card','remote','schedule'],[0.25,0.2,0.2,0.2,0.15])]);

add('verkada-event','verkada:event','Verkada','Command','json','Verkada security platform event',
  [F.ts,F.user,F.severity,F.status],
  {user:'user'},
  [enumF('device_type',['camera','access_control','sensor','alarm'],[0.3,0.25,0.25,0.2])]);

// ── Smart Building / IoT ─────────────────────────────────────────────────────
add('building-mgmt','bms:event','Johnson Controls','Metasys','json','Johnson Controls BMS event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('system',['hvac','lighting','fire','elevator','energy'],[0.25,0.2,0.2,0.2,0.15])]);

add('tridium-event','tridium:event','Tridium','Niagara','json','Tridium Niagara BAS event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('point_type',['temperature','humidity','pressure','co2','occupancy'],[0.25,0.2,0.2,0.2,0.15])]);

add('lutron-event','lutron:event','Lutron','Vive','json','Lutron lighting control event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('action',['on','off','dim','scene_recall','schedule'],[0.2,0.2,0.2,0.2,0.2]),intF('level_percent',0,100)]);

add('crestron-event','crestron:event','Crestron','NVX','json','Crestron AV control event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('device',['display','switcher','processor','shading','audio'],[0.2,0.2,0.2,0.2,0.2])]);

add('smartthings-event','smartthings:event','Samsung','SmartThings','json','Samsung SmartThings IoT event',
  [F.ts,F.status],
  {},
  [enumF('capability',['switch','motion','temperature','contact','lock'],[0.2,0.2,0.2,0.2,0.2]),enumF('value',['active','inactive','on','off','locked','unlocked'],[0.15,0.15,0.2,0.2,0.15,0.15])]);

// ── Gaming / Entertainment ───────────────────────────────────────────────────
add('unity-analytics','unity:event','Unity','Analytics','json','Unity game analytics event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['session_start','level_complete','purchase','achievement','ad_view'],[0.2,0.2,0.2,0.2,0.2])]);

add('steam-event','steam:event','Valve','Steamworks','json','Steam platform event',
  [F.ts,F.user,F.status,F.src_ip],
  {src_ip:'src_ip',user:'user'},
  [enumF('event_type',['login','purchase','achievement','workshop_upload','friend_request'],[0.25,0.2,0.2,0.2,0.15])]);

add('twitch-event','twitch:event','Twitch','API','json','Twitch platform event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['stream_online','stream_offline','subscription','follow','ban'],[0.2,0.15,0.25,0.2,0.2])]);

// ── Legal / eDiscovery ───────────────────────────────────────────────────────
add('relativity-audit','relativity:audit','Relativity','One','json','Relativity eDiscovery audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('object_type',['document','workspace','production','review','search'],[0.25,0.2,0.2,0.2,0.15])]);

add('nuix-audit','nuix:audit','Nuix','Discover','json','Nuix eDiscovery audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('operation',['ingest','search','export','tag','redact'],[0.25,0.2,0.2,0.2,0.15])]);

// ── HR / Workforce ───────────────────────────────────────────────────────────
add('bamboohr-event','bamboohr:event','BambooHR','HCM','json','BambooHR event log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('category',['employee','timeoff','benefit','onboarding','performance'],[0.2,0.2,0.2,0.2,0.2])]);

add('adp-event','adp:event','ADP','Workforce','json','ADP Workforce event log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('module',['payroll','time','benefits','talent','hr'],[0.2,0.2,0.2,0.2,0.2])]);

add('gusto-event','gusto:event','Gusto','Payroll','json','Gusto payroll event log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('event_type',['payroll_run','employee_added','benefit_change','tax_filing'],[0.3,0.25,0.25,0.2])]);

add('greenhouse-event','greenhouse:event','Greenhouse','ATS','json','Greenhouse ATS event log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('activity',['application_received','interview_scheduled','scorecard_submitted','offer_created','hired'],[0.25,0.2,0.2,0.2,0.15])]);

add('lever-event','lever:event','Lever','ATS','json','Lever recruiting event log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('stage',['new_lead','screen','phone_interview','onsite','offer','hired'],[0.2,0.15,0.2,0.15,0.15,0.15])]);

// ── Supply Chain / Logistics ─────────────────────────────────────────────────
add('sap-tm','sap:tm','SAP','Transportation Management','json','SAP TM event log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('document_type',['shipment','booking','delivery','invoice','customs'],[0.2,0.2,0.2,0.2,0.2])]);

add('oracle-wms','oracle:wms','Oracle','WMS','json','Oracle Warehouse Management event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('operation',['receive','put_away','pick','pack','ship'],[0.2,0.2,0.2,0.2,0.2])]);

add('manhattan-wms','manhattan:wms','Manhattan Associates','WMS','json','Manhattan WMS event log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('wave_type',['standard','rush','backorder','replenishment'],[0.35,0.25,0.2,0.2])]);

add('project44-event','project44:event','Project44','Visibility','json','Project44 supply chain event',
  [F.ts,F.status],
  {},
  [enumF('event_type',['pickup','in_transit','delay','delivered','exception'],[0.15,0.3,0.15,0.25,0.15]),enumF('mode',['truckload','ltl','ocean','air','rail'],[0.3,0.2,0.2,0.15,0.15])]);

add('fourkites-event','fourkites:event','FourKites','Visibility','json','FourKites supply chain event',
  [F.ts,F.status],
  {},
  [enumF('milestone',['origin_depart','customs_clear','port_arrive','destination_arrive','delivered'],[0.2,0.2,0.2,0.2,0.2])]);

// ── Energy / Utilities ───────────────────────────────────────────────────────
add('oasis-energy','oasis:event','OATI','webOASIS','json','OATI webOASIS energy market event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('transaction_type',['schedule','tag','curtailment','interchange','reserve'],[0.25,0.2,0.2,0.2,0.15])]);

add('osipi-event','osipi:event','AVEVA','OSIsoft PI','json','OSIsoft PI historian event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('point_type',['analog','digital','string','blob'],[0.35,0.3,0.2,0.15]),intF('value',0,1000)]);

add('itron-event','itron:event','Itron','AMI','json','Itron smart meter event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('event_type',['meter_read','outage','tamper','demand_response','firmware_update'],[0.3,0.2,0.15,0.2,0.15])]);

add('landis-gyr-event','landisgyr:event','Landis+Gyr','Gridstream','json','Landis+Gyr smart grid event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('event_type',['interval_data','demand','outage','restoration','voltage_event'],[0.3,0.2,0.15,0.2,0.15])]);

// ── Automotive / Fleet ───────────────────────────────────────────────────────
add('geotab-event','geotab:event','Geotab','MyGeotab','json','Geotab fleet telematics event',
  [F.ts,F.status],
  {},
  [enumF('event_type',['trip_start','trip_end','speed_violation','harsh_braking','idling'],[0.2,0.15,0.2,0.25,0.2]),intF('speed_kmh',0,200)]);

add('samsara-event','samsara:event','Samsara','Fleet','json','Samsara fleet management event',
  [F.ts,F.status],
  {},
  [enumF('alert_type',['speeding','harsh_event','geofence','driver_distraction','eld_violation'],[0.2,0.2,0.2,0.2,0.2])]);

add('verizon-connect','verizon:fleet','Verizon','Connect','json','Verizon Connect fleet event',
  [F.ts,F.status],
  {},
  [enumF('event_type',['ignition_on','ignition_off','geofence_enter','geofence_exit','maintenance_alert'],[0.2,0.15,0.2,0.2,0.25])]);

// ── Agriculture / Environment ────────────────────────────────────────────────
add('john-deere-event','deere:event','John Deere','Operations Center','json','John Deere Operations Center event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('operation',['planting','spraying','harvesting','tillage','transport'],[0.2,0.2,0.2,0.2,0.2])]);

add('climate-corp-event','climate:event','Climate','FieldView','json','Climate FieldView event',
  [F.ts,F.status],
  {},
  [enumF('data_type',['yield','soil_moisture','ndvi','weather','prescription'],[0.2,0.2,0.2,0.2,0.2])]);

// ── Aviation ─────────────────────────────────────────────────────────────────
add('flight-aware-event','flightaware:event','FlightAware','AeroAPI','json','FlightAware aviation event',
  [F.ts,F.status],
  {},
  [enumF('event_type',['departure','arrival','position_update','delay','diversion'],[0.2,0.2,0.25,0.2,0.15])]);

add('sita-event','sita:event','SITA','AT','json','SITA air transport event',
  [F.ts,F.status],
  {},
  [enumF('message_type',['type_b','aidx','pnr','departure','arrival'],[0.2,0.2,0.2,0.2,0.2])]);

// ── Insurance ────────────────────────────────────────────────────────────────
add('guidewire-event','guidewire:event','Guidewire','InsuranceSuite','json','Guidewire InsuranceSuite event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('module',['policy_center','claim_center','billing_center','contact_manager'],[0.3,0.25,0.25,0.2])]);

add('duck-creek-event','duckcreek:event','Duck Creek','Platform','json','Duck Creek insurance platform event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('transaction',['quote','bind','endorse','renew','cancel','claim'],[0.15,0.15,0.15,0.2,0.15,0.2])]);

// ── Construction / Real Estate ───────────────────────────────────────────────
add('procore-event','procore:event','Procore','Construction','json','Procore construction management event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('module',['project_mgmt','quality_safety','financials','field_productivity'],[0.3,0.25,0.25,0.2])]);

add('yardi-event','yardi:event','Yardi','Voyager','json','Yardi property management event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('module',['residential','commercial','accounting','maintenance','leasing'],[0.2,0.2,0.2,0.2,0.2])]);

// ── Developer Tools / Source Control ─────────────────────────────────────────
add('azure-repos','azure:repos','Microsoft','Azure Repos','json','Azure Repos audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('event_type',['push','pull_request','branch_policy','fork','review'],[0.25,0.25,0.15,0.15,0.2])]);

add('perforce-audit','perforce:audit','Perforce','Helix Core','json','Perforce Helix Core audit log',
  [F.ts,F.user,F.action,F.status,F.src_ip],
  {src_ip:'src_ip',user:'user'},
  [enumF('command',['sync','submit','edit','add','integrate'],[0.25,0.2,0.2,0.2,0.15])]);

add('svn-audit','svn:audit','Apache','Subversion','json','Apache Subversion audit log',
  [F.ts,F.user,F.action,F.src_ip],
  {src_ip:'src_ip',user:'user'},
  [enumF('operation',['commit','checkout','update','merge','lock'],[0.25,0.2,0.2,0.2,0.15])]);

add('artifactory-audit','artifactory:audit','JFrog','Artifactory','json','JFrog Artifactory audit log',
  [F.ts,F.user,F.action,F.status,F.src_ip],
  {src_ip:'src_ip',user:'user'},
  [enumF('event_type',['deploy','download','delete','copy','move','property'],[0.2,0.3,0.15,0.15,0.1,0.1])]);

add('nexus-audit','nexus:audit','Sonatype','Nexus','json','Sonatype Nexus Repository audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('repository_format',['maven','npm','docker','pypi','nuget'],[0.25,0.2,0.2,0.2,0.15])]);

add('harbor-audit','harbor:audit','Harbor','Registry','json','Harbor container registry audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('resource_type',['project','repository','artifact','tag','robot_account'],[0.2,0.25,0.2,0.2,0.15])]);

add('sonarqube-event','sonarqube:event','SonarSource','SonarQube','json','SonarQube code quality event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('issue_type',['bug','vulnerability','code_smell','security_hotspot'],[0.25,0.25,0.3,0.2]),F.severity]);

add('snyk-code','snyk:code','Snyk','Code','json','Snyk code analysis finding',
  [F.ts,F.severity,F.status],
  {},
  [enumF('category',['injection','xss','path_traversal','hardcoded_secret','insecure_crypto'],[0.2,0.2,0.2,0.2,0.2])]);

add('checkov-finding','checkov:finding','Bridgecrew','Checkov','json','Checkov IaC scan finding',
  [F.ts,F.severity,F.status],
  {},
  [enumF('framework',['terraform','cloudformation','kubernetes','arm','dockerfile'],[0.25,0.2,0.2,0.2,0.15]),F.result]);

add('semgrep-finding','semgrep:finding','Semgrep','SAST','json','Semgrep static analysis finding',
  [F.ts,F.severity,F.status],
  {},
  [enumF('language',['python','javascript','java','go','ruby','typescript'],[0.2,0.2,0.15,0.15,0.15,0.15])]);

add('dependabot-alert','dependabot:alert','GitHub','Dependabot','json','GitHub Dependabot security alert',
  [F.ts,F.severity,F.status],
  {},
  [enumF('ecosystem',['npm','pip','maven','rubygems','nuget','cargo'],[0.2,0.2,0.15,0.15,0.15,0.15]),intF('cvss_score',0,10)]);

add('renovate-event','renovate:event','Mend','Renovate','json','Renovate dependency update event',
  [F.ts,F.status],
  {},
  [enumF('update_type',['minor','patch','major','pin','digest'],[0.25,0.3,0.15,0.15,0.15]),enumF('manager',['npm','pip','docker','maven','bundler'],[0.25,0.2,0.2,0.2,0.15])]);

// ── Project Management ───────────────────────────────────────────────────────
add('clickup-event','clickup:event','ClickUp','Project Management','json','ClickUp project management event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('entity',['task','list','space','folder','goal'],[0.3,0.2,0.2,0.15,0.15])]);

add('linear-event','linear:event','Linear','Project Tracker','json','Linear issue tracker event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('entity',['issue','project','cycle','label','team'],[0.3,0.2,0.2,0.15,0.15])]);

add('shortcut-event','shortcut:event','Shortcut','Project Management','json','Shortcut project management event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('entity',['story','epic','milestone','iteration','label'],[0.3,0.2,0.2,0.15,0.15])]);

add('basecamp-event','basecamp:event','Basecamp','Basecamp','json','Basecamp project event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('resource',['todo','message','document','schedule','campfire'],[0.25,0.2,0.2,0.2,0.15])]);

add('smartsheet-event','smartsheet:event','Smartsheet','Smartsheet','json','Smartsheet audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('object_type',['sheet','report','dashboard','workspace','automation'],[0.25,0.2,0.2,0.2,0.15])]);

add('wrike-event','wrike:event','Wrike','Project Management','json','Wrike project management event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('entity',['task','project','folder','custom_field','workflow'],[0.3,0.2,0.2,0.15,0.15])]);

// ── Communication / Collaboration ────────────────────────────────────────────
add('teams-audit','teams:audit','Microsoft','Teams','json','Microsoft Teams audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('operation',['message_sent','meeting_started','file_shared','team_created','channel_created'],[0.3,0.2,0.2,0.15,0.15])]);

add('webex-audit','webex:audit','Cisco','Webex','json','Cisco Webex audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('event_type',['meeting','messaging','calling','space','admin'],[0.25,0.2,0.2,0.2,0.15])]);

add('ringcentral-event','ringcentral:event','RingCentral','MVP','json','RingCentral communication event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('action_type',['call','sms','fax','meeting','voicemail'],[0.3,0.2,0.15,0.2,0.15]),F.duration]);

add('dialpad-event','dialpad:event','Dialpad','AI Voice','json','Dialpad communication event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('channel',['voice','video','chat','sms','ai_assist'],[0.25,0.2,0.2,0.2,0.15]),F.duration]);

add('discord-event','discord:event','Discord','Platform','json','Discord platform audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('target_type',['guild','channel','member','role','message','webhook'],[0.15,0.2,0.2,0.15,0.15,0.15])]);

add('mattermost-audit','mattermost:audit','Mattermost','Platform','json','Mattermost audit log',
  [F.ts,F.user,F.action,F.status,F.src_ip],
  {src_ip:'src_ip',user:'user'},
  [enumF('event_type',['login','post','channel','team','plugin'],[0.2,0.25,0.2,0.2,0.15])]);

add('rocket-chat-audit','rocketchat:audit','Rocket.Chat','Platform','json','Rocket.Chat audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('resource',['message','channel','user','integration','admin'],[0.3,0.2,0.2,0.15,0.15])]);

// ── Design / Creative ────────────────────────────────────────────────────────
add('adobe-cc-audit','adobe:cc','Adobe','Creative Cloud','json','Adobe Creative Cloud audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('app',['photoshop','illustrator','premiere','indesign','xd','acrobat'],[0.2,0.15,0.2,0.15,0.15,0.15])]);

add('sketch-event','sketch:event','Sketch','Sketch','json','Sketch workspace event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('object_type',['document','artboard','symbol','library','prototype'],[0.25,0.2,0.2,0.2,0.15])]);

add('invision-event','invision:event','InVision','Platform','json','InVision design platform event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('resource',['prototype','screen','comment','board','freehand'],[0.25,0.2,0.2,0.2,0.15])]);

// ── CRM / Marketing ─────────────────────────────────────────────────────────
add('marketo-event','marketo:event','Marketo','Engage','json','Marketo marketing automation event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('activity',['email_send','form_fill','web_visit','score_change','list_add'],[0.25,0.2,0.2,0.2,0.15])]);

add('pardot-event','pardot:event','Salesforce','Pardot','json','Pardot marketing event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('activity_type',['email_click','form_submission','page_view','opportunity_created','score_increase'],[0.25,0.2,0.2,0.2,0.15])]);

add('eloqua-event','eloqua:event','Oracle','Eloqua','json','Oracle Eloqua marketing event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('asset_type',['email','landing_page','form','campaign','segment'],[0.25,0.2,0.2,0.2,0.15])]);

add('dynamics-audit','dynamics:audit','Microsoft','Dynamics 365','json','Dynamics 365 CRM audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('entity',['account','contact','opportunity','case','lead'],[0.2,0.2,0.2,0.2,0.2])]);

add('zoho-audit','zoho:audit','Zoho','CRM','json','Zoho CRM audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('module',['leads','contacts','deals','accounts','campaigns'],[0.2,0.2,0.2,0.2,0.2])]);

add('pipedrive-event','pipedrive:event','Pipedrive','CRM','json','Pipedrive CRM event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('object_type',['deal','person','organization','activity','product'],[0.25,0.2,0.2,0.2,0.15])]);

// ── Cloud Storage ────────────────────────────────────────────────────────────
add('wasabi-event','wasabi:event','Wasabi','Cloud Storage','json','Wasabi cloud storage event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('api',['PutObject','GetObject','DeleteObject','ListBucket','HeadObject'],[0.25,0.3,0.15,0.2,0.1])]);

add('backblaze-event','backblaze:event','Backblaze','B2','json','Backblaze B2 storage event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('api',['b2_upload_file','b2_download_file','b2_delete_file','b2_list_file_names'],[0.3,0.3,0.2,0.2])]);

add('minio-audit','minio:audit','MinIO','ObjectStore','json','MinIO object storage audit log',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('api',['PutObject','GetObject','DeleteObject','ListObjects','HeadBucket'],[0.25,0.3,0.15,0.2,0.1])]);

add('ceph-log','ceph:log','Ceph','Storage','json','Ceph distributed storage log',
  [F.ts,F.level,F.hostname],
  {},
  [enumF('daemon',['osd','mon','mds','rgw','mgr'],[0.25,0.2,0.15,0.2,0.2]),F.msg]);

add('netapp-audit','netapp:audit','NetApp','ONTAP','json','NetApp ONTAP audit log',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('operation',['cifs_open','nfs_read','lun_resize','snap_create','vol_move'],[0.25,0.2,0.2,0.2,0.15])]);

add('pure-storage-event','purestorage:event','Pure Storage','FlashArray','json','Pure Storage FlashArray event',
  [F.ts,F.severity,F.hostname,F.status],
  {},
  [enumF('component',['volume','host','port','controller','drive'],[0.25,0.2,0.2,0.2,0.15])]);

add('dell-emc-event','dell:emc','Dell','PowerStore','json','Dell PowerStore storage event',
  [F.ts,F.severity,F.hostname,F.status],
  {},
  [enumF('event_type',['alert','audit','performance','config_change','hardware'],[0.2,0.2,0.2,0.2,0.2])]);

// ── Virtualization ───────────────────────────────────────────────────────────
add('vmware-vcenter','vmware:vcenter','VMware','vCenter','json','VMware vCenter event log',
  [F.ts,F.user,F.hostname,F.status],
  {user:'user'},
  [enumF('event_type',['vm_powered_on','vm_powered_off','vm_migrated','snapshot_created','resource_pool_change'],[0.2,0.15,0.2,0.25,0.2])]);

add('vmware-esxi','vmware:esxi','VMware','ESXi','json','VMware ESXi host event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('subsystem',['hostd','vpxa','vmkernel','fdm','vobd'],[0.25,0.2,0.2,0.2,0.15])]);

add('vmware-nsx','vmware:nsx','VMware','NSX','json','VMware NSX event log',
  [F.ts,F.src_ip,F.dst_ip,F.action,F.severity],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('component',['firewall','router','load_balancer','vpn','ids'],[0.25,0.2,0.2,0.2,0.15])]);

add('proxmox-event','proxmox:event','Proxmox','VE','json','Proxmox VE event log',
  [F.ts,F.user,F.hostname,F.status],
  {user:'user'},
  [enumF('action',['vm_start','vm_stop','vm_migrate','container_start','backup'],[0.2,0.15,0.2,0.2,0.25])]);

add('hyper-v-event','hyperv:event','Microsoft','Hyper-V','json','Microsoft Hyper-V event log',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('event_type',['vm_created','vm_started','vm_stopped','checkpoint_created','live_migration'],[0.2,0.2,0.2,0.2,0.2])]);

add('kvm-event','kvm:event','KVM','Libvirt','json','KVM/Libvirt virtualization event',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('operation',['domain_start','domain_stop','domain_migrate','snapshot','storage_pool'],[0.25,0.2,0.2,0.2,0.15])]);

add('nutanix-event','nutanix:event','Nutanix','AHV','json','Nutanix AHV cluster event',
  [F.ts,F.hostname,F.severity,F.status],
  {},
  [enumF('entity_type',['vm','host','cluster','storage_container','protection_domain'],[0.25,0.2,0.2,0.2,0.15])]);

add('citrix-xenserver','citrix:xenserver','Citrix','XenServer','json','Citrix XenServer event log',
  [F.ts,F.hostname,F.status],
  {},
  [enumF('event_type',['vm_start','vm_shutdown','vm_migrate','snapshot','pool_join'],[0.2,0.2,0.2,0.2,0.2])]);

// ── Service Mesh / API Gateway ───────────────────────────────────────────────
add('istio-access','istio:access','Istio','Service Mesh','json','Istio service mesh access log',
  [F.ts,F.src_ip,F.dst_ip,F.method,F.code,F.duration],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('response_flag',['none','NR','UO','UF','URX'],[0.6,0.1,0.1,0.1,0.1])]);

add('linkerd-access','linkerd:access','Linkerd','Service Mesh','json','Linkerd service mesh access log',
  [F.ts,F.src_ip,F.dst_ip,F.method,F.code,F.duration],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('tls',['true','false'],[0.8,0.2])]);

add('kong-log','kong:log','Kong','API Gateway','json','Kong API gateway access log',
  [F.ts,F.client_ip,F.method,F.code,F.duration],
  {src_ip:'client_ip'},
  [enumF('service',['auth-service','user-service','product-service','order-service'],[0.3,0.25,0.25,0.2])]);

add('tyk-log','tyk:log','Tyk','API Gateway','json','Tyk API gateway access log',
  [F.ts,F.client_ip,F.method,F.code,F.duration],
  {src_ip:'client_ip'},
  [enumF('api_name',['users','orders','products','auth','webhooks'],[0.25,0.2,0.2,0.2,0.15])]);

add('apigee-log','apigee:log','Google','Apigee','json','Apigee API management log',
  [F.ts,F.client_ip,F.method,F.code,F.duration,F.user],
  {src_ip:'client_ip',user:'user'},
  [enumF('proxy_name',['payments-api','users-api','catalog-api','auth-api'],[0.3,0.25,0.25,0.2])]);

add('mulesoft-log','mulesoft:log','MuleSoft','Anypoint','json','MuleSoft Anypoint API log',
  [F.ts,F.client_ip,F.method,F.code,F.duration],
  {src_ip:'client_ip'},
  [enumF('api_name',['system-api','process-api','experience-api','connector'],[0.3,0.25,0.25,0.2])]);

add('gravitee-log','gravitee:log','Gravitee','APIM','json','Gravitee API management log',
  [F.ts,F.client_ip,F.method,F.code,F.duration],
  {src_ip:'client_ip'},
  [enumF('plan',['free','silver','gold','enterprise'],[0.3,0.25,0.25,0.2])]);

// ── Serverless / Edge ────────────────────────────────────────────────────────
add('aws-lambda-edge','aws:lambda:edge','AWS','Lambda@Edge','json','AWS Lambda@Edge invocation log',
  [F.ts,F.status,F.duration,F.region],
  {},
  [enumF('event_type',['viewer-request','origin-request','origin-response','viewer-response'],[0.3,0.25,0.25,0.2])]);

add('cloudflare-pages','cloudflare:pages','Cloudflare','Pages','json','Cloudflare Pages deployment event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['build_started','build_success','build_failed','deployed'],[0.25,0.35,0.15,0.25]),F.duration]);

add('deno-deploy','deno:deploy','Deno','Deploy','json','Deno Deploy function event',
  [F.ts,F.status,F.duration,F.region],
  {},
  [enumF('trigger',['http','cron','websocket','kv'],[0.5,0.2,0.15,0.15])]);

add('firebase-event','firebase:event','Google','Firebase','json','Firebase project event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('service',['auth','firestore','storage','hosting','functions','messaging'],[0.2,0.2,0.15,0.15,0.15,0.15])]);

add('azure-static-web','azure:staticweb','Microsoft','Static Web Apps','json','Azure Static Web Apps event',
  [F.ts,F.status],
  {},
  [enumF('event_type',['build','deploy','function_invocation','auth','custom_domain'],[0.2,0.25,0.25,0.15,0.15]),F.duration]);

// ── Secret Management ────────────────────────────────────────────────────────
add('doppler-audit','doppler:audit','Doppler','SecretOps','json','Doppler secrets management audit',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('resource',['secret','project','environment','service_token','config'],[0.25,0.2,0.2,0.2,0.15])]);

add('onepassword-event','onepassword:event','1Password','Business','json','1Password business event',
  [F.ts,F.user,F.action,F.status,F.src_ip],
  {src_ip:'src_ip',user:'user'},
  [enumF('category',['signin','item_usage','vault','team','two_factor'],[0.25,0.25,0.2,0.15,0.15])]);

add('bitwarden-event','bitwarden:event','Bitwarden','Enterprise','json','Bitwarden enterprise event',
  [F.ts,F.user,F.action,F.status,F.src_ip],
  {src_ip:'src_ip',user:'user'},
  [enumF('event_type',['login','item_viewed','item_created','collection_updated','policy_updated'],[0.3,0.2,0.2,0.15,0.15])]);

add('lastpass-event','lastpass:event','LastPass','Enterprise','json','LastPass enterprise event',
  [F.ts,F.user,F.action,F.status,F.src_ip],
  {src_ip:'src_ip',user:'user'},
  [enumF('action_type',['login','site_accessed','shared','policy_change','mfa_event'],[0.25,0.25,0.2,0.15,0.15])]);

// ── Network Access Control ───────────────────────────────────────────────────
add('portnox-event','portnox:event','Portnox','Clear','json','Portnox Clear NAC event',
  [F.ts,F.src_ip,F.user,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('auth_result',['success','failure','quarantine','remediation'],[0.5,0.2,0.15,0.15])]);

add('forescout-nac','forescout:nac','Forescout','eyeControl','json','Forescout NAC event',
  [F.ts,F.src_ip,F.hostname,F.status],
  {src_ip:'src_ip'},
  [enumF('action',['allow','deny','quarantine','limit','remediate'],[0.4,0.15,0.2,0.15,0.1]),F.os]);

add('packetfence-event','packetfence:event','PacketFence','NAC','json','PacketFence NAC event',
  [F.ts,F.src_ip,F.user,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('violation',['none','os_mismatch','scan_failed','auth_failed','quarantine'],[0.4,0.15,0.15,0.15,0.15])]);

// ── Load Testing / Performance ───────────────────────────────────────────────
add('k6-result','k6:result','Grafana','k6','json','Grafana k6 load test result',
  [F.ts,F.status,F.duration],
  {},
  [enumF('metric',['http_req_duration','http_req_failed','vus','iterations','data_received'],[0.25,0.2,0.2,0.2,0.15]),intF('value',0,10000)]);

add('jmeter-result','jmeter:result','Apache','JMeter','json','Apache JMeter test result',
  [F.ts,F.status,F.duration],
  {},
  [enumF('sampler',['HTTP Request','JDBC Request','JMS Publisher','WebSocket'],[0.4,0.25,0.2,0.15]),intF('response_code',200,503)]);

add('gatling-result','gatling:result','Gatling','Load Test','json','Gatling load test result',
  [F.ts,F.status,F.duration],
  {},
  [enumF('scenario',['browse','search','checkout','api_stress'],[0.3,0.25,0.25,0.2]),intF('users',1,10000)]);

add('locust-result','locust:result','Locust','Load Test','json','Locust load test result',
  [F.ts,F.status,F.duration],
  {},
  [enumF('task',['browse_page','submit_form','api_call','websocket_connect'],[0.3,0.25,0.25,0.2]),intF('rps',1,10000)]);

// ── WiFi / Wireless Management ───────────────────────────────────────────────
add('ruckus-wireless','ruckus:event','Ruckus','SmartZone','json','Ruckus wireless event',
  [F.ts,F.client_ip,F.hostname,F.status],
  {src_ip:'client_ip'},
  [enumF('event_type',['association','disassociation','authentication','roaming','rogue_ap'],[0.25,0.2,0.2,0.2,0.15])]);

add('extreme-wireless','extreme:wireless','Extreme','ExtremeCloud','json','Extreme Networks wireless event',
  [F.ts,F.client_ip,F.hostname,F.status],
  {src_ip:'client_ip'},
  [enumF('event_type',['client_connect','client_disconnect','ap_up','ap_down','rogue_detected'],[0.25,0.2,0.2,0.2,0.15])]);

add('mist-event','mist:event','Juniper','Mist AI','json','Juniper Mist AI wireless event',
  [F.ts,F.client_ip,F.hostname,F.status],
  {src_ip:'client_ip'},
  [enumF('event_type',['client_session','ap_event','rogue_ap','anomaly','marvis_action'],[0.25,0.2,0.15,0.2,0.2])]);

// ── Container Registry / Package ─────────────────────────────────────────────
add('quay-audit','quay:audit','Red Hat','Quay','json','Red Hat Quay registry audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('resource',['repository','tag','manifest','team','robot_account'],[0.25,0.2,0.2,0.2,0.15])]);

add('ghcr-event','ghcr:event','GitHub','Container Registry','json','GitHub Container Registry event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('operation',['push','pull','delete','tag','create'],[0.25,0.3,0.15,0.15,0.15])]);

add('ecr-event','aws:ecr','AWS','ECR','json','AWS ECR container registry event',
  [F.ts,F.user,F.action,F.status,F.region],
  {user:'user'},
  [enumF('api_call',['PutImage','GetDownloadUrlForLayer','BatchDeleteImage','DescribeImages'],[0.3,0.3,0.2,0.2])]);

add('acr-event','azure:acr','Microsoft','Azure Container Registry','json','Azure Container Registry event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('operation',['push','pull','delete','quarantine','chart_push'],[0.3,0.3,0.15,0.1,0.15])]);

add('gcr-event','gcp:gcr','Google','Artifact Registry','json','Google Artifact Registry event',
  [F.ts,F.user,F.action,F.status,F.region],
  {user:'user'},
  [enumF('format',['docker','maven','npm','python','apt'],[0.3,0.2,0.2,0.15,0.15])]);

// ── AI/ML Platforms ──────────────────────────────────────────────────────────
add('sagemaker-event','aws:sagemaker','AWS','SageMaker','json','AWS SageMaker ML event',
  [F.ts,F.user,F.status,F.region],
  {user:'user'},
  [enumF('action',['CreateTrainingJob','CreateEndpoint','InvokeEndpoint','CreateNotebook','CreatePipeline'],[0.2,0.2,0.25,0.2,0.15]),F.duration]);

add('azure-ml-event','azure:ml','Microsoft','Azure ML','json','Azure Machine Learning event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('operation',['run_submitted','model_registered','endpoint_created','dataset_created','compute_created'],[0.25,0.2,0.2,0.2,0.15]),F.duration]);

add('vertex-ai-event','gcp:vertexai','Google','Vertex AI','json','Google Vertex AI event',
  [F.ts,F.user,F.status,F.region],
  {user:'user'},
  [enumF('operation',['training','prediction','pipeline','feature_store','model_monitoring'],[0.25,0.25,0.2,0.15,0.15]),F.duration]);

add('mlflow-event','mlflow:event','MLflow','Tracking','json','MLflow experiment tracking event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('action',['create_run','log_metric','log_model','register_model','create_experiment'],[0.25,0.2,0.2,0.2,0.15])]);

add('wandb-event','wandb:event','Weights & Biases','Platform','json','Weights & Biases experiment event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['run_started','run_finished','artifact_created','sweep_created','report_created'],[0.25,0.25,0.2,0.15,0.15])]);

add('openai-audit','openai:audit','OpenAI','API','json','OpenAI API audit log',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('model',['gpt-4','gpt-3.5','dall-e-3','whisper','embeddings'],[0.3,0.25,0.15,0.15,0.15]),intF('tokens',1,100000)]);

add('huggingface-event','huggingface:event','Hugging Face','Hub','json','Hugging Face Hub event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('resource',['model','dataset','space','discussion','api_key'],[0.25,0.2,0.2,0.2,0.15])]);

// ── Blockchain / Web3 ────────────────────────────────────────────────────────
add('ethereum-event','ethereum:event','Ethereum','Node','json','Ethereum node event',
  [F.ts,F.status],
  {},
  [enumF('event_type',['new_block','transaction','contract_call','sync','peer_connect'],[0.2,0.25,0.2,0.2,0.15]),intF('gas_used',21000,30000000)]);

add('chainalysis-alert','chainalysis:alert','Chainalysis','KYT','json','Chainalysis KYT alert',
  [F.ts,F.severity],
  {},
  [enumF('category',['sanctions','darknet','ransomware','stolen_funds','mixer'],[0.2,0.2,0.2,0.2,0.2]),F.risk]);

// ── CDN / Edge Computing ────────────────────────────────────────────────────
add('fastly-log','fastly:log','Fastly','CDN','json','Fastly CDN access log',
  [F.ts,F.client_ip,F.method,F.code,F.bytes,F.duration],
  {src_ip:'client_ip'},
  [enumF('cache_status',['HIT','MISS','PASS','ERROR','STALE'],[0.45,0.25,0.15,0.1,0.05])]);

add('bunny-cdn-log','bunnycdn:log','BunnyCDN','CDN','json','BunnyCDN access log',
  [F.ts,F.client_ip,F.method,F.code,F.bytes],
  {src_ip:'client_ip'},
  [enumF('cache_hit',['HIT','MISS','BYPASS'],[0.5,0.35,0.15])]);

add('keycdn-log','keycdn:log','KeyCDN','CDN','json','KeyCDN access log',
  [F.ts,F.client_ip,F.code,F.bytes],
  {src_ip:'client_ip'},
  [enumF('status',['hit','miss','expired','stale'],[0.45,0.3,0.15,0.1])]);

// ── Miscellaneous Security ───────────────────────────────────────────────────
add('duo-admin','duo:admin','Duo','Admin','json','Duo Security admin audit log',
  [F.ts,F.user,F.action,F.status,F.src_ip],
  {src_ip:'src_ip',user:'user'},
  [enumF('object',['user','phone','integration','policy','admin'],[0.2,0.2,0.2,0.2,0.2])]);

add('yubico-event','yubico:event','Yubico','YubiEnterprise','json','YubiEnterprise delivery event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('key_type',['yubikey_5','yubikey_5c','yubikey_bio','security_key'],[0.3,0.25,0.2,0.25])]);

add('beyond-identity','beyondidentity:event','Beyond Identity','Platform','json','Beyond Identity passwordless event',
  [F.ts,F.user,F.src_ip,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('auth_method',['platform_authenticator','device_trust','passkey'],[0.4,0.35,0.25])]);

add('specops-event','specops:event','Specops','Password','json','Specops password management event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['password_reset','password_change','policy_violation','mfa_challenge'],[0.3,0.25,0.25,0.2])]);

add('thales-hsm','thales:hsm','Thales','Luna','json','Thales Luna HSM audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('operation',['sign','encrypt','decrypt','key_generate','key_wrap'],[0.25,0.2,0.2,0.2,0.15])]);

add('entrust-pki','entrust:pki','Entrust','PKI','json','Entrust PKI certificate event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('cert_action',['issue','renew','revoke','suspend','reinstate'],[0.3,0.25,0.2,0.15,0.1])]);

add('venafi-event','venafi:event','Venafi','TLS Protect','json','Venafi certificate management event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('object_type',['certificate','ca','policy','workflow','discovery'],[0.3,0.2,0.2,0.15,0.15])]);

add('sectigo-event','sectigo:event','Sectigo','Certificate Manager','json','Sectigo certificate management event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('cert_type',['ssl_dv','ssl_ov','ssl_ev','code_signing','smime'],[0.25,0.2,0.2,0.2,0.15])]);

// ── Data Loss Prevention ─────────────────────────────────────────────────────
add('forcepoint-dlp','forcepoint:dlp','Forcepoint','DLP','json','Forcepoint DLP event',
  [F.ts,F.user,F.src_ip,F.severity,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('channel',['email','web','endpoint','cloud','network'],[0.2,0.2,0.2,0.2,0.2]),enumF('policy',['pii','phi','pci','ip','classified'],[0.2,0.2,0.2,0.2,0.2])]);

add('trellix-dlp','trellix:dlp','Trellix','DLP','json','Trellix DLP event',
  [F.ts,F.user,F.severity,F.status],
  {user:'user'},
  [enumF('channel',['email','web','removable_media','clipboard','print'],[0.2,0.2,0.2,0.2,0.2]),enumF('action',['block','monitor','encrypt','notify','quarantine'],[0.2,0.2,0.2,0.2,0.2])]);

add('code42-incydr','code42:incydr','Code42','Incydr','json','Code42 Incydr insider risk event',
  [F.ts,F.user,F.severity,F.status],
  {user:'user'},
  [enumF('indicator',['file_upload','cloud_share','removable_media','airdrop','untrusted_domain'],[0.2,0.2,0.2,0.2,0.2]),F.risk]);

add('nightfall-event','nightfall:event','Nightfall','DLP','json','Nightfall cloud DLP event',
  [F.ts,F.user,F.severity,F.status],
  {user:'user'},
  [enumF('integration',['slack','github','jira','confluence','google_drive'],[0.2,0.2,0.2,0.2,0.2]),enumF('detector',['credit_card','ssn','api_key','password','phi'],[0.2,0.2,0.2,0.2,0.2])]);

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH 3 — Even more sourcetypes to exceed 1000
// ═══════════════════════════════════════════════════════════════════════════════

// ── Networking — Switches / Routers ──────────────────────────────────────────
add('hp-procurve','hp:procurve','HPE','ProCurve','syslog','HP ProCurve switch log',
  [F.ts,F.hostname,F.severity],{},
  [enumF('event_type',['port_up','port_down','auth_fail','spanning_tree','vlan_change'],[0.2,0.2,0.2,0.2,0.2])]);

add('dell-switch','dell:switch','Dell','PowerSwitch','syslog','Dell PowerSwitch event log',
  [F.ts,F.hostname,F.severity,F.status],{},
  [enumF('module',['stp','lacp','vlan','acl','bgp'],[0.2,0.2,0.2,0.2,0.2])]);

add('brocade-switch','brocade:switch','Brocade','FOS','syslog','Brocade Fibre Channel switch log',
  [F.ts,F.hostname,F.severity],{},
  [enumF('event_type',['port_online','port_offline','zone_change','fabric_event','login'],[0.2,0.2,0.2,0.2,0.2])]);

add('extreme-switch','extreme:switch','Extreme','EXOS','syslog','Extreme Networks EXOS switch log',
  [F.ts,F.hostname,F.severity,F.status],{},
  [enumF('component',['port','vlan','stp','ospf','bgp'],[0.2,0.2,0.2,0.2,0.2])]);

add('cumulus-switch','cumulus:switch','NVIDIA','Cumulus','syslog','Cumulus Linux switch log',
  [F.ts,F.hostname,F.level],{},
  [enumF('daemon',['switchd','frr','clagd','netd','ptmd'],[0.25,0.2,0.2,0.2,0.15])]);

add('sonic-switch','sonic:switch','SONiC','SONiC','syslog','SONiC network OS switch log',
  [F.ts,F.hostname,F.level],{},
  [enumF('service',['bgp','swss','syncd','teamd','lldp'],[0.25,0.2,0.2,0.2,0.15])]);

// ── Linux / Unix Logs ────────────────────────────────────────────────────────
add('linux-syslog','linux:syslog','Linux','syslog','syslog','Linux syslog event',
  [F.ts,F.hostname,F.level],{},
  [enumF('facility',['auth','cron','daemon','kern','mail','user'],[0.2,0.15,0.2,0.2,0.1,0.15]),F.msg]);

add('linux-auth','linux:auth','Linux','auth.log','syslog','Linux authentication log',
  [F.ts,F.hostname,F.user,F.src_ip,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('service',['sshd','sudo','su','login','pam'],[0.3,0.2,0.15,0.15,0.2])]);

add('linux-dpkg','linux:dpkg','Linux','dpkg','syslog','Linux dpkg package log',
  [F.ts,F.hostname,F.status],{},
  [enumF('action',['install','upgrade','remove','configure','trigproc'],[0.25,0.25,0.15,0.2,0.15])]);

add('linux-yum','linux:yum','Linux','yum','syslog','Linux yum/dnf package log',
  [F.ts,F.hostname,F.user,F.status],
  {user:'user'},
  [enumF('action',['install','update','erase','downgrade','reinstall'],[0.3,0.3,0.15,0.15,0.1])]);

add('linux-systemd','linux:systemd','Linux','systemd','json','Linux systemd journal event',
  [F.ts,F.hostname,F.level],{},
  [enumF('unit',['sshd','nginx','docker','kubelet','cron'],[0.2,0.2,0.2,0.2,0.2]),F.msg]);

add('linux-selinux','linux:selinux','Linux','SELinux','syslog','Linux SELinux audit event',
  [F.ts,F.hostname,F.status],{},
  [enumF('type',['AVC','USER_AUTH','SYSCALL','PATH','CWD'],[0.3,0.2,0.2,0.15,0.15])]);

add('linux-apparmor','linux:apparmor','Linux','AppArmor','syslog','Linux AppArmor security event',
  [F.ts,F.hostname,F.status],{},
  [enumF('mode',['ALLOWED','DENIED','AUDITING','STATUS'],[0.35,0.3,0.2,0.15])]);

add('freebsd-log','freebsd:log','FreeBSD','syslog','syslog','FreeBSD system log',
  [F.ts,F.hostname,F.level],{},
  [enumF('facility',['auth','security','daemon','kern','local0'],[0.2,0.2,0.2,0.2,0.2]),F.msg]);

add('solaris-audit','solaris:audit','Oracle','Solaris','json','Oracle Solaris audit event',
  [F.ts,F.user,F.hostname,F.status],
  {user:'user'},
  [enumF('event_type',['login','logout','exec','file_access','process'],[0.2,0.15,0.25,0.2,0.2])]);

add('aix-audit','aix:audit','IBM','AIX','json','IBM AIX audit event',
  [F.ts,F.user,F.hostname,F.status],
  {user:'user'},
  [enumF('event_class',['USER_Login','FILE_Unlink','PROC_Execute','FS_Object','AUD_Proc'],[0.25,0.2,0.2,0.2,0.15])]);

// ── Windows Advanced Logs ────────────────────────────────────────────────────
add('windows-dns','windows:dns','Microsoft','DNS Server','json','Windows DNS Server analytics log',
  [F.ts,F.client_ip,F.hostname],
  {src_ip:'client_ip'},
  [enumF('query_type',['A','AAAA','PTR','MX','SRV','CNAME'],[0.3,0.15,0.15,0.1,0.15,0.15]),enumF('rcode',['NOERROR','NXDOMAIN','SERVFAIL','REFUSED'],[0.7,0.15,0.1,0.05])]);

add('windows-firewall','windows:firewall','Microsoft','Windows Firewall','json','Windows Defender Firewall log',
  [F.ts,F.src_ip,F.dst_ip,F.proto,F.port,F.action],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [F.direction]);

add('windows-wmi','windows:wmi','Microsoft','WMI','json','Windows WMI activity event',
  [F.ts,F.user,F.hostname,F.status],
  {user:'user'},
  [enumF('operation',['ExecQuery','ExecMethod','CreateInstance','GetObject'],[0.35,0.25,0.2,0.2])]);

add('windows-taskscheduler','windows:taskscheduler','Microsoft','Task Scheduler','json','Windows Task Scheduler event',
  [F.ts,F.user,F.hostname,F.status],
  {user:'user'},
  [enumF('event_type',['task_created','task_started','task_completed','task_failed','task_deleted'],[0.15,0.3,0.3,0.15,0.1])]);

add('windows-bits','windows:bits','Microsoft','BITS','json','Windows BITS transfer event',
  [F.ts,F.user,F.hostname,F.status],
  {user:'user'},
  [enumF('transfer_type',['download','upload','upload_reply'],[0.5,0.3,0.2]),F.bytes]);

add('windows-applocker','windows:applocker','Microsoft','AppLocker','json','Windows AppLocker event',
  [F.ts,F.user,F.hostname,F.status],
  {user:'user'},
  [enumF('rule_type',['exe','script','msi','dll','appx'],[0.3,0.2,0.15,0.2,0.15]),enumF('action',['allowed','denied','audited'],[0.5,0.3,0.2])]);

add('windows-wdac','windows:wdac','Microsoft','WDAC','json','Windows WDAC code integrity event',
  [F.ts,F.hostname,F.status],{},
  [enumF('policy_action',['allowed','blocked','audit'],[0.5,0.3,0.2]),enumF('file_type',['exe','dll','driver','script'],[0.3,0.25,0.25,0.2])]);

add('windows-etw','windows:etw','Microsoft','ETW','json','Windows ETW trace event',
  [F.ts,F.hostname],{},
  [enumF('provider',['Microsoft-Windows-Kernel-Process','Microsoft-Windows-DNS-Client','Microsoft-Windows-Security-Auditing'],[0.35,0.35,0.3]),F.level]);

add('ad-replication','ad:replication','Microsoft','Active Directory','json','AD replication event',
  [F.ts,F.hostname,F.status],{},
  [enumF('operation',['replicate','sync','topology_change','lingering_object','conflict'],[0.3,0.25,0.2,0.15,0.1])]);

add('ad-group-policy','ad:gpo','Microsoft','Group Policy','json','AD Group Policy processing event',
  [F.ts,F.hostname,F.user,F.status],
  {user:'user'},
  [enumF('extension',['registry','security','scripts','folder_redirection','software_install'],[0.25,0.2,0.2,0.2,0.15])]);

// ── Collaboration / Document Management ──────────────────────────────────────
add('sharepoint-audit','sharepoint:audit','Microsoft','SharePoint','json','SharePoint audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('operation',['FileAccessed','FileModified','FileUploaded','FileDeleted','SiteCreated'],[0.3,0.2,0.2,0.15,0.15])]);

add('onedrive-audit','onedrive:audit','Microsoft','OneDrive','json','OneDrive audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('operation',['FileUploaded','FileDownloaded','FileShared','FileSynced','FileDeleted'],[0.25,0.25,0.2,0.15,0.15])]);

add('google-drive-audit','google:drive','Google','Drive','json','Google Drive audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('event_type',['create','edit','view','download','share','delete'],[0.15,0.2,0.25,0.15,0.15,0.1])]);

add('docusign-event','docusign:event','DocuSign','eSignature','json','DocuSign eSignature event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('event_type',['envelope_sent','envelope_signed','envelope_completed','envelope_voided','envelope_declined'],[0.25,0.3,0.25,0.1,0.1])]);

add('adobesign-event','adobesign:event','Adobe','Sign','json','Adobe Sign event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('event_type',['agreement_created','agreement_signed','agreement_completed','agreement_cancelled'],[0.3,0.3,0.25,0.15])]);

// ── ERP / Business ───────────────────────────────────────────────────────────
add('netsuite-audit','netsuite:audit','Oracle','NetSuite','json','NetSuite ERP audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('record_type',['sales_order','invoice','customer','item','journal_entry'],[0.2,0.2,0.2,0.2,0.2])]);

add('sage-audit','sage:audit','Sage','Intacct','json','Sage Intacct audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('module',['general_ledger','accounts_payable','accounts_receivable','purchasing','project'],[0.2,0.2,0.2,0.2,0.2])]);

add('quickbooks-event','quickbooks:event','Intuit','QuickBooks','json','QuickBooks audit log',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('entity',['invoice','payment','customer','vendor','account'],[0.2,0.2,0.2,0.2,0.2])]);

add('xero-event','xero:event','Xero','Accounting','json','Xero accounting event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('resource',['invoice','payment','contact','bank_transaction','expense_claim'],[0.2,0.2,0.2,0.2,0.2])]);

// ── Data Governance / Catalog ────────────────────────────────────────────────
add('collibra-audit','collibra:audit','Collibra','Data Intelligence','json','Collibra data governance audit',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('asset_type',['data_set','column','business_term','policy','domain'],[0.2,0.2,0.2,0.2,0.2])]);

add('alation-audit','alation:audit','Alation','Data Catalog','json','Alation data catalog audit',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('object_type',['data_source','table','query','article','glossary_term'],[0.2,0.2,0.2,0.2,0.2])]);

add('atlan-audit','atlan:audit','Atlan','Data Catalog','json','Atlan data workspace audit',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('asset_type',['table','column','query','dashboard','dbt_model'],[0.2,0.2,0.2,0.2,0.2])]);

add('datahub-event','datahub:event','DataHub','Metadata','json','DataHub metadata event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('entity_type',['dataset','dashboard','pipeline','user','tag'],[0.25,0.2,0.2,0.2,0.15])]);

add('openmetadata-event','openmetadata:event','OpenMetadata','Platform','json','OpenMetadata event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('entity',['table','topic','dashboard','pipeline','ml_model'],[0.25,0.2,0.2,0.2,0.15])]);

add('montecarlo-event','montecarlo:event','Monte Carlo','Data Observability','json','Monte Carlo data observability event',
  [F.ts,F.severity,F.status],{},
  [enumF('incident_type',['freshness','volume','schema','distribution','custom'],[0.2,0.2,0.2,0.2,0.2])]);

add('greatexpectations-result','gx:result','Great Expectations','Validation','json','Great Expectations validation result',
  [F.ts,F.status],{},
  [enumF('expectation_type',['expect_column_values_not_null','expect_table_row_count','expect_column_values_unique','expect_column_values_in_set'],[0.25,0.25,0.25,0.25]),F.result]);

add('soda-result','soda:result','Soda','Data Quality','json','Soda data quality check result',
  [F.ts,F.status],{},
  [enumF('check_type',['freshness','validity','missing','duplicate','anomaly'],[0.2,0.2,0.2,0.2,0.2]),F.result]);

// ── CI/CD Security / DAST ────────────────────────────────────────────────────
add('stackhawk-finding','stackhawk:finding','StackHawk','DAST','json','StackHawk DAST finding',
  [F.ts,F.severity,F.status],{},
  [enumF('category',['injection','xss','misconfig','auth','info_leak'],[0.2,0.2,0.2,0.2,0.2])]);

add('gitleaks-finding','gitleaks:finding','Gitleaks','Secret Scanning','json','Gitleaks secret detection finding',
  [F.ts,F.severity,F.status],{},
  [enumF('rule',['aws-access-key','private-key','generic-password','github-token','slack-token'],[0.2,0.2,0.2,0.2,0.2])]);

add('trufflehog-finding','trufflehog:finding','TruffleHog','Secret Scanning','json','TruffleHog secret detection finding',
  [F.ts,F.severity,F.status],{},
  [enumF('source',['git','filesystem','s3','github','syslog'],[0.3,0.2,0.2,0.2,0.1])]);

add('trivy-finding','trivy:finding','Aqua','Trivy','json','Trivy container scan finding',
  [F.ts,F.severity,F.status],{},
  [enumF('class',['os-pkgs','library','config','secret','license'],[0.25,0.25,0.2,0.15,0.15]),intF('cvss_score',0,10)]);

add('grype-finding','grype:finding','Anchore','Grype','json','Grype vulnerability finding',
  [F.ts,F.severity,F.status],{},
  [enumF('type',['apk','deb','rpm','go','npm','pip'],[0.15,0.15,0.15,0.2,0.2,0.15])]);

// ── Observability — Logging ──────────────────────────────────────────────────
add('fluentd-event','fluentd:event','Fluentd','Fluentd','json','Fluentd log router event',
  [F.ts,F.level,F.hostname],{},
  [enumF('plugin',['in_tail','in_forward','out_elasticsearch','out_s3','filter_record_transformer'],[0.2,0.2,0.2,0.2,0.2])]);

add('fluentbit-event','fluentbit:event','Fluent Bit','Fluent Bit','json','Fluent Bit log processor event',
  [F.ts,F.level,F.hostname],{},
  [enumF('plugin',['tail','forward','es','s3','kubernetes'],[0.2,0.2,0.2,0.2,0.2])]);

add('vector-event','vector:event','Timber','Vector','json','Vector data pipeline event',
  [F.ts,F.level,F.hostname],{},
  [enumF('component_type',['source','transform','sink'],[0.35,0.3,0.35])]);

add('logstash-event','logstash:event','Elastic','Logstash','json','Logstash pipeline event',
  [F.ts,F.level,F.hostname],{},
  [enumF('plugin_type',['input','filter','output'],[0.35,0.3,0.35]),F.msg]);

add('cribl-event','cribl:event','Cribl','Stream','json','Cribl Stream internal event',
  [F.ts,F.level,F.hostname,F.status],{},
  [enumF('component',['source','pipeline','destination','route','pack'],[0.2,0.2,0.2,0.2,0.2])]);

add('rsyslog-event','rsyslog:event','Rsyslog','Rsyslog','syslog','Rsyslog stats event',
  [F.ts,F.hostname,F.level],{},
  [enumF('module',['imudp','imtcp','omfwd','omfile','mmjsonparse'],[0.2,0.2,0.2,0.2,0.2])]);

add('syslogng-event','syslogng:event','syslog-ng','syslog-ng','syslog','syslog-ng internal event',
  [F.ts,F.hostname,F.level],{},
  [enumF('module',['source','destination','filter','parser','rewrite'],[0.2,0.2,0.2,0.2,0.2])]);

// ── Network Packet Capture / Forensics ───────────────────────────────────────
add('arkime-session','arkime:session','Arkime','Full Packet Capture','json','Arkime (Moloch) session log',
  [F.ts,F.src_ip,F.dst_ip,F.proto,F.port,F.bytes],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [F.duration]);

add('networkminer-event','networkminer:event','NetworkMiner','Forensics','json','NetworkMiner forensic analysis event',
  [F.ts,F.src_ip,F.dst_ip,F.proto],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('artifact_type',['file','image','credential','dns','certificate'],[0.2,0.2,0.2,0.2,0.2])]);

add('rita-alert','rita:alert','Active Countermeasures','RITA','json','RITA beacon detection alert',
  [F.ts,F.src_ip,F.dst_ip,F.severity],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('detection',['beacon','dns_tunnel','long_connection','c2_over_dns'],[0.3,0.25,0.25,0.2]),F.risk]);

// ── Email / Spam Filtering ───────────────────────────────────────────────────
add('postfix-log','postfix:log','Postfix','MTA','syslog','Postfix mail transfer agent log',
  [F.ts,F.client_ip,F.status],
  {src_ip:'client_ip'},
  [enumF('action',['sent','deferred','bounced','rejected','delivered'],[0.4,0.15,0.15,0.15,0.15]),F.id]);

add('sendmail-log','sendmail:log','Sendmail','MTA','syslog','Sendmail MTA log',
  [F.ts,F.client_ip,F.status],
  {src_ip:'client_ip'},
  [enumF('stat',['Sent','Deferred','User_unknown','Connection_refused'],[0.5,0.2,0.15,0.15])]);

add('dovecot-log','dovecot:log','Dovecot','IMAP','syslog','Dovecot IMAP/POP3 server log',
  [F.ts,F.user,F.client_ip,F.status],
  {src_ip:'client_ip',user:'user'},
  [enumF('service',['imap-login','pop3-login','lmtp','auth'],[0.35,0.2,0.25,0.2])]);

add('zimbra-audit','zimbra:audit','Zimbra','Collaboration','json','Zimbra audit event',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('protocol',['imap','pop3','soap','http','smtp'],[0.2,0.15,0.25,0.2,0.2])]);

add('spamassassin-log','spamassassin:log','SpamAssassin','SpamAssassin','syslog','SpamAssassin filter log',
  [F.ts,F.client_ip],
  {src_ip:'client_ip'},
  [enumF('result',['clean','spam','probable_spam'],[0.5,0.3,0.2]),intF('score',-5,25)]);

// ── Database Monitoring / Proxy ──────────────────────────────────────────────
add('pgbouncer-log','pgbouncer:log','PgBouncer','Connection Pooler','json','PgBouncer connection pooler log',
  [F.ts,F.client_ip,F.user,F.status],
  {src_ip:'client_ip',user:'user'},
  [enumF('event_type',['login','logout','query','server_connect','pool_full'],[0.2,0.15,0.3,0.2,0.15])]);

add('proxysql-log','proxysql:log','ProxySQL','ProxySQL','json','ProxySQL query log',
  [F.ts,F.client_ip,F.user,F.status,F.duration],
  {src_ip:'client_ip',user:'user'},
  [enumF('command',['SELECT','INSERT','UPDATE','DELETE','SET'],[0.35,0.2,0.15,0.1,0.2])]);

add('maxscale-log','maxscale:log','MariaDB','MaxScale','json','MariaDB MaxScale proxy log',
  [F.ts,F.client_ip,F.user,F.status],
  {src_ip:'client_ip',user:'user'},
  [enumF('module',['readwritesplit','readconnroute','binlogrouter','avrorouter'],[0.35,0.25,0.2,0.2])]);

// ── More Cloud Services ──────────────────────────────────────────────────────
add('aws-athena','aws:athena','AWS','Athena','json','AWS Athena query audit log',
  [F.ts,F.user,F.status,F.duration,F.region],
  {user:'user'},
  [intF('data_scanned_mb',1,100000)]);

add('aws-msk','aws:msk','AWS','MSK','json','AWS Managed Streaming for Kafka log',
  [F.ts,F.status,F.region],{},
  [enumF('event_type',['broker_log','authenticator','authorizer','request_handler'],[0.3,0.25,0.25,0.2])]);

add('aws-transfer','aws:transfer','AWS','Transfer Family','json','AWS Transfer Family event',
  [F.ts,F.user,F.src_ip,F.action,F.status,F.region],
  {src_ip:'src_ip',user:'user'},
  [enumF('protocol',['sftp','ftps','ftp','as2'],[0.4,0.25,0.2,0.15])]);

add('aws-workspaces','aws:workspaces','AWS','WorkSpaces','json','AWS WorkSpaces event',
  [F.ts,F.user,F.src_ip,F.status,F.region],
  {src_ip:'src_ip',user:'user'},
  [enumF('event_type',['session_start','session_end','rebuild','reboot','connection_failed'],[0.3,0.2,0.15,0.15,0.2])]);

add('aws-networkfirewall','aws:networkfirewall','AWS','Network Firewall','json','AWS Network Firewall log',
  [F.ts,F.src_ip,F.dst_ip,F.proto,F.action,F.region],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('rule_group',['default','stateful','stateless','custom'],[0.25,0.25,0.25,0.25])]);

add('azure-bastion','azure:bastion','Microsoft','Bastion','json','Azure Bastion session log',
  [F.ts,F.user,F.src_ip,F.status,F.duration],
  {src_ip:'src_ip',user:'user'},
  [enumF('target_type',['vm','vmss'],[0.7,0.3])]);

add('azure-waf','azure:waf','Microsoft','WAF','json','Azure WAF log',
  [F.ts,F.client_ip,F.action,F.severity],
  {src_ip:'client_ip'},
  [enumF('rule_type',['OWASP','custom','bot','rate_limit'],[0.3,0.25,0.25,0.2]),F.code]);

add('azure-ddos','azure:ddos','Microsoft','DDoS Protection','json','Azure DDoS Protection log',
  [F.ts,F.dst_ip,F.severity,F.status],
  {dst_ip:'dst_ip'},
  [enumF('attack_type',['volumetric','protocol','application'],[0.4,0.35,0.25]),intF('pps',1000,10000000)]);

add('gcp-securitycommand','gcp:scc','Google','Security Command Center','json','GCP Security Command Center finding',
  [F.ts,F.severity,F.status],{},
  [enumF('finding_class',['THREAT','VULNERABILITY','MISCONFIGURATION','OBSERVATION'],[0.25,0.25,0.25,0.25]),F.cloud]);

add('gcp-dlp','gcp:dlp','Google','DLP','json','GCP DLP finding',
  [F.ts,F.severity,F.status],{},
  [enumF('info_type',['PHONE_NUMBER','EMAIL_ADDRESS','CREDIT_CARD_NUMBER','US_SOCIAL_SECURITY_NUMBER','IP_ADDRESS'],[0.2,0.2,0.2,0.2,0.2])]);

// ── Testing / QA ─────────────────────────────────────────────────────────────
add('browserstack-event','browserstack:event','BrowserStack','Automate','json','BrowserStack test event',
  [F.ts,F.user,F.status,F.duration],
  {user:'user'},
  [enumF('browser',['chrome','firefox','safari','edge','ie'],[0.3,0.2,0.2,0.2,0.1])]);

add('saucelabs-event','saucelabs:event','Sauce Labs','Automate','json','Sauce Labs test event',
  [F.ts,F.user,F.status,F.duration],
  {user:'user'},
  [enumF('platform',['windows','macos','linux','android','ios'],[0.25,0.2,0.2,0.2,0.15])]);

add('cypress-result','cypress:result','Cypress','E2E Testing','json','Cypress test result',
  [F.ts,F.status,F.duration],{},
  [enumF('result',['passed','failed','pending','skipped'],[0.6,0.2,0.1,0.1]),intF('test_count',1,500)]);

add('playwright-result','playwright:result','Microsoft','Playwright','json','Playwright test result',
  [F.ts,F.status,F.duration],{},
  [enumF('browser',['chromium','firefox','webkit'],[0.4,0.3,0.3]),intF('test_count',1,500)]);

// ── Incident Management ──────────────────────────────────────────────────────
add('statuspage-event','statuspage:event','Atlassian','Statuspage','json','Statuspage incident event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('incident_status',['investigating','identified','monitoring','resolved'],[0.25,0.25,0.25,0.25])]);

add('incident-io-event','incidentio:event','incident.io','Platform','json','incident.io incident event',
  [F.ts,F.user,F.status,F.severity],
  {user:'user'},
  [enumF('lifecycle',['triage','active','post_incident','closed'],[0.25,0.3,0.25,0.2])]);

add('rootly-event','rootly:event','Rootly','Incident Mgmt','json','Rootly incident management event',
  [F.ts,F.user,F.status,F.severity],
  {user:'user'},
  [enumF('action',['incident_created','status_update','postmortem','action_item','follow_up'],[0.2,0.25,0.2,0.2,0.15])]);

add('firehydrant-event','firehydrant:event','FireHydrant','Incident Mgmt','json','FireHydrant incident event',
  [F.ts,F.user,F.status,F.severity],
  {user:'user'},
  [enumF('milestone',['started','detected','mitigated','resolved','postmortem'],[0.2,0.2,0.2,0.2,0.2])]);

// ── Identity Threat Detection ────────────────────────────────────────────────
add('silverfort-event','silverfort:event','Silverfort','Platform','json','Silverfort identity protection event',
  [F.ts,F.user,F.src_ip,F.status,F.risk],
  {src_ip:'src_ip',user:'user'},
  [enumF('auth_type',['kerberos','ntlm','ldap','rdp','ssh'],[0.2,0.2,0.2,0.2,0.2])]);

add('semperis-event','semperis:event','Semperis','DSP','json','Semperis AD threat detection event',
  [F.ts,F.user,F.severity,F.status],
  {user:'user'},
  [enumF('indicator',['dcsync','golden_ticket','skeleton_key','ad_replication','group_change'],[0.2,0.2,0.2,0.2,0.2])]);

add('crowdstrike-identity','crowdstrike:identity','CrowdStrike','Identity Protection','json','CrowdStrike identity threat event',
  [F.ts,F.user,F.src_ip,F.severity],
  {src_ip:'src_ip',user:'user'},
  [enumF('threat_type',['lateral_movement','credential_theft','privilege_escalation','honey_token'],[0.25,0.25,0.25,0.25]),F.risk]);

// ── More misc to push over 1000 ─────────────────────────────────────────────
add('opsgenie-incident','opsgenie:incident','Atlassian','OpsGenie','json','OpsGenie incident event',
  [F.ts,F.user,F.status,F.severity],
  {user:'user'},
  [enumF('action',['created','acknowledged','escalated','resolved','closed'],[0.2,0.2,0.2,0.2,0.2])]);

add('notion-api','notion:api','Notion','API','json','Notion API audit event',
  [F.ts,F.user,F.action,F.status,F.src_ip],
  {src_ip:'src_ip',user:'user'},
  [enumF('endpoint',['pages','databases','blocks','users','search'],[0.2,0.2,0.2,0.2,0.2])]);

add('retool-audit','retool:audit','Retool','Platform','json','Retool internal tool audit',
  [F.ts,F.user,F.action,F.status,F.src_ip],
  {src_ip:'src_ip',user:'user'},
  [enumF('resource',['query','app','workflow','resource_connection'],[0.3,0.25,0.25,0.2])]);

add('appsmith-audit','appsmith:audit','Appsmith','Platform','json','Appsmith low-code audit',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('entity',['application','page','datasource','query','widget'],[0.2,0.2,0.2,0.2,0.2])]);

add('budibase-audit','budibase:audit','Budibase','Platform','json','Budibase low-code audit',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('resource',['app','table','automation','screen','user'],[0.2,0.2,0.2,0.2,0.2])]);

add('temporal-event','temporal:event','Temporal','Workflow','json','Temporal workflow event',
  [F.ts,F.status],{},
  [enumF('event_type',['WorkflowStarted','WorkflowCompleted','ActivityStarted','ActivityCompleted','TimerFired'],[0.2,0.2,0.2,0.2,0.2]),F.id]);

add('prefect-event','prefect:event','Prefect','Orchestrator','json','Prefect workflow event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('state',['Scheduled','Running','Completed','Failed','Cancelled'],[0.15,0.25,0.3,0.15,0.15]),F.duration]);

add('airflow-event','airflow:event','Apache','Airflow','json','Apache Airflow DAG event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['dag_run','task_instance','connection','variable','pool'],[0.25,0.25,0.2,0.15,0.15]),F.duration]);

add('dagster-event','dagster:event','Dagster','Dagster','json','Dagster orchestration event',
  [F.ts,F.status],{},
  [enumF('event_type',['RUN_START','RUN_SUCCESS','RUN_FAILURE','STEP_START','STEP_SUCCESS'],[0.2,0.2,0.15,0.25,0.2]),F.duration]);

add('luigi-event','luigi:event','Spotify','Luigi','json','Luigi task scheduler event',
  [F.ts,F.status],{},
  [enumF('task_status',['PENDING','RUNNING','DONE','FAILED','DISABLED'],[0.15,0.2,0.35,0.15,0.15]),F.duration]);

add('mage-event','mage:event','Mage','AI Pipeline','json','Mage AI pipeline event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('block_type',['data_loader','transformer','data_exporter','sensor','custom'],[0.2,0.25,0.2,0.2,0.15]),F.duration]);

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH 4 — Final push to exceed 1000
// ═══════════════════════════════════════════════════════════════════════════════

// ── More VPN / Zero Trust ────────────────────────────────────────────────────
add('tailscale-event','tailscale:event','Tailscale','VPN','json','Tailscale mesh VPN event',
  [F.ts,F.user,F.src_ip,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('event_type',['node_connected','node_disconnected','acl_change','auth','exit_node'],[0.25,0.2,0.2,0.2,0.15])]);

add('zerotier-event','zerotier:event','ZeroTier','VPN','json','ZeroTier network event',
  [F.ts,F.src_ip,F.status],
  {src_ip:'src_ip'},
  [enumF('event_type',['member_join','member_leave','network_created','auth_success','auth_fail'],[0.2,0.15,0.15,0.3,0.2])]);

add('twingate-event','twingate:event','Twingate','ZTNA','json','Twingate zero trust access event',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('resource_type',['ssh','rdp','http','tcp','database'],[0.2,0.2,0.25,0.2,0.15])]);

add('zpa-event','zscaler:zpa:event','Zscaler','ZPA Browser','json','Zscaler ZPA browser access event',
  [F.ts,F.user,F.src_ip,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('app_type',['web','ssh','rdp','vnc','tcp'],[0.3,0.2,0.2,0.15,0.15])]);

add('perimeter81-event','perimeter81:event','Perimeter 81','ZTNA','json','Perimeter 81 ZTNA event',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('gateway',['us-east','us-west','eu-central','ap-south'],[0.3,0.25,0.25,0.2])]);

// ── Crypto / Key Management ─────────────────────────────────────────────────
add('aws-cloudhsm','aws:cloudhsm','AWS','CloudHSM','json','AWS CloudHSM audit log',
  [F.ts,F.user,F.action,F.status,F.region],
  {user:'user'},
  [enumF('operation',['generateKey','sign','encrypt','decrypt','wrapKey'],[0.2,0.25,0.2,0.2,0.15])]);

add('azure-keyvault-audit','azure:keyvault:audit','Microsoft','Key Vault','json','Azure Key Vault detailed audit',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('object_type',['key','secret','certificate','storage_account'],[0.3,0.3,0.25,0.15])]);

// ── More SaaS Productivity ───────────────────────────────────────────────────
add('calendly-event','calendly:event','Calendly','Scheduling','json','Calendly scheduling event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['invitee_created','invitee_canceled','event_type_created','routing_form_submitted'],[0.35,0.2,0.25,0.2])]);

add('loom-event','loom:event','Loom','Video','json','Loom video recording event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('event_type',['recording_created','shared','viewed','commented','transcribed'],[0.2,0.2,0.25,0.2,0.15])]);

add('typeform-event','typeform:event','Typeform','Forms','json','Typeform form submission event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['form_response','form_created','form_updated','workspace_created'],[0.4,0.2,0.25,0.15])]);

add('survey-monkey-event','surveymonkey:event','SurveyMonkey','Surveys','json','SurveyMonkey event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['response_completed','survey_created','collector_created','response_exported'],[0.35,0.25,0.2,0.2])]);

add('zapier-event','zapier:event','Zapier','Automation','json','Zapier workflow event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['zap_run_success','zap_run_error','zap_turned_on','zap_turned_off'],[0.4,0.2,0.2,0.2])]);

add('make-event','make:event','Make','Automation','json','Make (Integromat) automation event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['scenario_run','webhook_received','error_handler','module_executed'],[0.35,0.25,0.2,0.2])]);

add('n8n-event','n8n:event','n8n','Workflow Automation','json','n8n workflow automation event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['workflow_success','workflow_error','webhook_received','manual_trigger'],[0.35,0.2,0.25,0.2])]);

add('power-automate-event','powerautomate:event','Microsoft','Power Automate','json','Power Automate flow event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('flow_type',['automated','instant','scheduled','desktop'],[0.3,0.25,0.25,0.2])]);

// ── Analytics / BI ───────────────────────────────────────────────────────────
add('tableau-audit','tableau:audit','Salesforce','Tableau','json','Tableau Server audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('object_type',['workbook','datasource','view','project','site'],[0.25,0.2,0.2,0.2,0.15])]);

add('powerbi-audit','powerbi:audit','Microsoft','Power BI','json','Power BI audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('artifact',['report','dashboard','dataset','app','workspace'],[0.25,0.2,0.2,0.2,0.15])]);

add('looker-audit','looker:audit','Google','Looker','json','Looker audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('entity',['look','dashboard','explore','model','connection'],[0.2,0.2,0.2,0.2,0.2])]);

add('metabase-audit','metabase:audit','Metabase','Analytics','json','Metabase audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('model',['card','dashboard','collection','database','table'],[0.25,0.2,0.2,0.2,0.15])]);

add('superset-audit','superset:audit','Apache','Superset','json','Apache Superset audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('resource',['chart','dashboard','dataset','database','query'],[0.2,0.2,0.2,0.2,0.2])]);

add('grafana-audit','grafana:audit','Grafana','Grafana','json','Grafana audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('resource',['dashboard','datasource','user','folder','alert_rule'],[0.25,0.2,0.2,0.2,0.15])]);

add('redash-audit','redash:audit','Redash','Analytics','json','Redash audit event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('object_type',['query','dashboard','data_source','visualization'],[0.3,0.25,0.25,0.2])]);

// ── Cloud Cost / FinOps ──────────────────────────────────────────────────────
add('cloudhealth-event','cloudhealth:event','VMware','CloudHealth','json','CloudHealth FinOps event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('event_type',['cost_anomaly','rightsizing','reservation','budget_alert'],[0.3,0.25,0.25,0.2])]);

add('kubecost-event','kubecost:event','Kubecost','Cost Management','json','Kubecost Kubernetes cost event',
  [F.ts,F.status],{},
  [enumF('alert_type',['budget_exceeded','efficiency','idle_resources','allocation_change'],[0.3,0.25,0.25,0.2]),intF('daily_cost_cents',100,100000)]);

add('spot-event','spot:event','NetApp','Spot','json','Spot by NetApp cloud optimization event',
  [F.ts,F.status,F.region],{},
  [enumF('action',['scale_up','scale_down','rebalance','replace','recover'],[0.2,0.2,0.2,0.2,0.2])]);

add('vantage-event','vantage:event','Vantage','Cost Platform','json','Vantage cloud cost event',
  [F.ts,F.status],{},
  [enumF('report_type',['cost_report','savings_plan','reserved_instance','anomaly'],[0.3,0.25,0.25,0.2]),F.cloud]);

// ── SSE / Browser Isolation ──────────────────────────────────────────────────
add('palo-prisma-sase','prisma:sase','Palo Alto','Prisma SASE','json','Prisma SASE event log',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('service',['remote_browser','ztna','swg','casb','dlp'],[0.2,0.2,0.2,0.2,0.2])]);

add('talon-event','talon:event','Talon','Enterprise Browser','json','Talon secure enterprise browser event',
  [F.ts,F.user,F.src_ip,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('policy_action',['allow','block','isolate','watermark','dlp_alert'],[0.3,0.15,0.2,0.2,0.15])]);

add('island-event','island:event','Island','Enterprise Browser','json','Island enterprise browser event',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('policy',['clipboard','download','upload','printing','screenshot'],[0.2,0.2,0.2,0.2,0.2])]);

// ── Network Automation ───────────────────────────────────────────────────────
add('nautobot-event','nautobot:event','Nautobot','NetDevOps','json','Nautobot network automation event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('object_type',['device','interface','ip_address','vlan','cable','circuit'],[0.2,0.15,0.2,0.15,0.15,0.15])]);

add('nornir-event','nornir:event','Nornir','Automation','json','Nornir network automation event',
  [F.ts,F.hostname,F.status],{},
  [enumF('task',['netmiko_send_command','napalm_get','nornir_netbox','netmiko_send_config'],[0.3,0.25,0.25,0.2])]);

add('batfish-result','batfish:result','Batfish','Network Analysis','json','Batfish network analysis result',
  [F.ts,F.status],{},
  [enumF('analysis',['reachability','routing','acl','diff','compliance'],[0.2,0.2,0.2,0.2,0.2]),F.result]);

// ── DNS Security ─────────────────────────────────────────────────────────────
add('dnstap-event','dnstap:event','dnstap','DNS Monitoring','json','dnstap DNS monitoring event',
  [F.ts,F.client_ip],
  {src_ip:'client_ip'},
  [enumF('msg_type',['CLIENT_QUERY','CLIENT_RESPONSE','AUTH_QUERY','AUTH_RESPONSE','RESOLVER_QUERY'],[0.25,0.2,0.2,0.2,0.15])]);

add('passivedns-event','passivedns:event','PassiveDNS','Collection','json','Passive DNS collection event',
  [F.ts,F.client_ip],
  {src_ip:'client_ip'},
  [enumF('rrtype',['A','AAAA','CNAME','NS','MX','TXT'],[0.3,0.15,0.15,0.15,0.1,0.15])]);

add('dnsfilter-event','dnsfilter:event','DNSFilter','DNS Security','json','DNSFilter DNS security event',
  [F.ts,F.client_ip,F.status],
  {src_ip:'client_ip'},
  [enumF('category',['allowed','blocked_malware','blocked_phishing','blocked_botnet','blocked_policy'],[0.4,0.15,0.15,0.15,0.15])]);

// ── Compliance Scanning ──────────────────────────────────────────────────────
add('inspec-result','inspec:result','Chef','InSpec','json','Chef InSpec compliance result',
  [F.ts,F.hostname,F.status],{},
  [enumF('profile',['cis_benchmark','disa_stig','pci_dss','hipaa','custom'],[0.2,0.2,0.2,0.2,0.2]),F.result]);

add('openscap-result','openscap:result','OpenSCAP','Scanner','json','OpenSCAP compliance scan result',
  [F.ts,F.hostname,F.status],{},
  [enumF('rule_result',['pass','fail','error','notapplicable','notchecked'],[0.4,0.25,0.1,0.15,0.1]),F.severity]);

add('lynis-result','lynis:result','CISOfy','Lynis','json','Lynis security audit result',
  [F.ts,F.hostname,F.status],{},
  [enumF('category',['authentication','networking','storage','software','kernel','hardening'],[0.15,0.2,0.15,0.2,0.15,0.15]),F.severity]);

add('ansible-lint-result','ansiblelint:result','Ansible','Lint','json','Ansible Lint validation result',
  [F.ts,F.status],{},
  [enumF('tag',['yaml','jinja','deprecated','risky','no-changed-when'],[0.2,0.2,0.2,0.2,0.2]),F.severity]);

add('terraform-sentinel','sentinel:result','HashiCorp','Sentinel','json','Terraform Sentinel policy result',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('enforcement',['hard_mandatory','soft_mandatory','advisory'],[0.35,0.35,0.3]),F.result]);

add('opa-decision','opa:decision','OPA','Gatekeeper','json','OPA policy decision event',
  [F.ts,F.status],{},
  [enumF('decision',['allow','deny'],[0.6,0.4]),enumF('policy',['authz','rbac','network','resource'],[0.25,0.25,0.25,0.25])]);

// ── More cloud / SaaS ───────────────────────────────────────────────────────
add('gitlab-ci','gitlab:ci','GitLab','CI/CD','json','GitLab CI/CD pipeline event',
  [F.ts,F.user,F.status,F.duration],
  {user:'user'},
  [enumF('pipeline_stage',['build','test','deploy','review','cleanup'],[0.2,0.25,0.25,0.15,0.15])]);

add('github-actions','github:actions','GitHub','Actions','json','GitHub Actions workflow event',
  [F.ts,F.user,F.status,F.duration],
  {user:'user'},
  [enumF('event',['push','pull_request','schedule','workflow_dispatch','release'],[0.3,0.25,0.15,0.15,0.15])]);

add('vercel-log','vercel:log','Vercel','Edge','json','Vercel edge function log',
  [F.ts,F.client_ip,F.code,F.duration],
  {src_ip:'client_ip'},
  [enumF('region',['iad1','sfo1','lhr1','hnd1','cdg1'],[0.25,0.2,0.2,0.2,0.15])]);

add('planetscale-query','planetscale:query','PlanetScale','Insights','json','PlanetScale query insights',
  [F.ts,F.user,F.status,F.duration],
  {user:'user'},
  [enumF('query_type',['SELECT','INSERT','UPDATE','DELETE','ALTER'],[0.35,0.2,0.2,0.15,0.1])]);

add('upstash-event','upstash:event','Upstash','Serverless Redis','json','Upstash serverless Redis event',
  [F.ts,F.status],{},
  [enumF('command',['GET','SET','DEL','LPUSH','ZADD','HSET'],[0.25,0.2,0.1,0.15,0.15,0.15]),F.duration]);

add('turso-event','turso:event','Turso','Edge Database','json','Turso edge SQLite event',
  [F.ts,F.user,F.status,F.duration],
  {user:'user'},
  [enumF('query_type',['SELECT','INSERT','UPDATE','DELETE','PRAGMA'],[0.35,0.2,0.15,0.15,0.15])]);

add('xata-event','xata:event','Xata','Serverless Database','json','Xata serverless database event',
  [F.ts,F.user,F.action,F.status],
  {user:'user'},
  [enumF('operation',['search','insert','update','delete','aggregate'],[0.3,0.2,0.15,0.15,0.2])]);

add('convex-event','convex:event','Convex','Backend','json','Convex backend platform event',
  [F.ts,F.status,F.duration],{},
  [enumF('function_type',['query','mutation','action','http_action'],[0.3,0.3,0.2,0.2])]);

// ── Physical / Environmental ─────────────────────────────────────────────────
add('apc-ups','apc:ups','APC','Smart-UPS','json','APC UPS event log',
  [F.ts,F.hostname,F.severity],{},
  [enumF('event_type',['on_battery','on_line','low_battery','overload','bypass','self_test'],[0.15,0.3,0.1,0.1,0.1,0.25]),intF('battery_pct',0,100)]);

add('eaton-ups','eaton:ups','Eaton','UPS','json','Eaton UPS event log',
  [F.ts,F.hostname,F.severity],{},
  [enumF('event',['utility_failure','utility_restored','battery_low','overload','temp_alarm'],[0.2,0.2,0.15,0.15,0.3])]);

add('liebert-cooling','liebert:cooling','Vertiv','Liebert','json','Vertiv Liebert cooling event',
  [F.ts,F.hostname,F.severity],{},
  [enumF('alarm',['high_temp','low_temp','high_humidity','low_humidity','fan_fail','compressor_fail'],[0.2,0.15,0.15,0.1,0.2,0.2])]);

add('netbotz-event','netbotz:event','APC','NetBotz','json','APC NetBotz environmental event',
  [F.ts,F.hostname,F.severity],{},
  [enumF('sensor',['temperature','humidity','door','fluid','smoke','vibration'],[0.2,0.2,0.15,0.15,0.15,0.15])]);

add('raritan-pdu','raritan:pdu','Raritan','PDU','json','Raritan PDU event log',
  [F.ts,F.hostname,F.severity],{},
  [enumF('event',['outlet_on','outlet_off','overcurrent','undercurrent','sensor_alert'],[0.2,0.15,0.25,0.2,0.2])]);

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH 5 — Final 30 to break 1000
// ═══════════════════════════════════════════════════════════════════════════════

add('crowdstrike-spotlight','crowdstrike:spotlight','CrowdStrike','Spotlight','json','CrowdStrike Spotlight vulnerability event',
  [F.ts,F.hostname,F.severity,F.status],{},
  [intF('cvss_score',0,10),enumF('remediation',['patch','workaround','accept_risk','pending'],[0.35,0.25,0.2,0.2])]);

add('sentinelone-activity','sentinelone:activity','SentinelOne','Singularity','json','SentinelOne activity event',
  [F.ts,F.user,F.hostname,F.action,F.status],
  {user:'user'},
  [enumF('activity_type',['agent_installed','threat_detected','policy_updated','exclusion_created'],[0.25,0.3,0.25,0.2])]);

add('rapid7-idr','rapid7:idr','Rapid7','InsightIDR','json','Rapid7 InsightIDR detection',
  [F.ts,F.user,F.src_ip,F.severity],
  {src_ip:'src_ip',user:'user'},
  [enumF('detection_rule',['ingress_auth','lateral_movement','malware','hash_match','custom'],[0.25,0.2,0.2,0.15,0.2])]);

add('cisco-secure-endpoint','cisco:amp','Cisco','Secure Endpoint','json','Cisco Secure Endpoint event',
  [F.ts,F.hostname,F.severity,F.status],{},
  [enumF('event_type',['threat_detected','threat_quarantined','scan_completed','policy_update'],[0.3,0.25,0.25,0.2])]);

add('sophos-xgs','sophos:xgs','Sophos','XGS Firewall','syslog','Sophos XGS firewall log',
  [F.ts,F.src_ip,F.dst_ip,F.action,F.proto,F.port],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [F.bytes]);

add('versa-sdwan','versa:sdwan','Versa','SD-WAN','json','Versa SD-WAN event log',
  [F.ts,F.src_ip,F.dst_ip,F.status],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('event_type',['path_switch','link_down','link_up','policy_change','sla_violation'],[0.2,0.2,0.2,0.2,0.2])]);

add('silverpeak-sdwan','silverpeak:sdwan','Aruba','EdgeConnect','json','Silver Peak SD-WAN event log',
  [F.ts,F.hostname,F.severity,F.status],{},
  [enumF('event_type',['tunnel_up','tunnel_down','failover','boost','path_change'],[0.2,0.2,0.2,0.2,0.2])]);

add('vmware-velocloud','velocloud:event','VMware','VeloCloud','json','VMware VeloCloud SD-WAN event',
  [F.ts,F.hostname,F.severity,F.status],{},
  [enumF('category',['link','vpn','path','security','system'],[0.2,0.2,0.2,0.2,0.2])]);

add('cisco-sdwan','cisco:sdwan','Cisco','Viptela','json','Cisco SD-WAN event',
  [F.ts,F.hostname,F.severity,F.status],{},
  [enumF('event_type',['bfd_state','control_connection','omp','policy','security'],[0.2,0.2,0.2,0.2,0.2])]);

add('fortinet-sdwan','fortinet:sdwan','Fortinet','SD-WAN','json','FortiGate SD-WAN event',
  [F.ts,F.src_ip,F.dst_ip,F.status],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('event',['member_alive','member_dead','sla_pass','sla_fail','route_change'],[0.2,0.2,0.2,0.2,0.2])]);

add('aryaka-sdwan','aryaka:event','Aryaka','SmartConnect','json','Aryaka SD-WAN event',
  [F.ts,F.hostname,F.status],{},
  [enumF('metric',['latency','jitter','packet_loss','throughput','availability'],[0.2,0.2,0.2,0.2,0.2])]);

add('cloudgenix-event','cloudgenix:event','Palo Alto','CloudGenix','json','CloudGenix SD-WAN event',
  [F.ts,F.hostname,F.severity,F.status],{},
  [enumF('category',['circuit','vpn','policy','application','security'],[0.2,0.2,0.2,0.2,0.2])]);

add('peplink-event','peplink:event','Peplink','SD-WAN','json','Peplink SD-WAN event',
  [F.ts,F.hostname,F.status],{},
  [enumF('event_type',['wan_connected','wan_disconnected','speedfusion','cellular_signal','failover'],[0.2,0.2,0.2,0.2,0.2])]);

add('elastic-siem','elastic:siem','Elastic','Security','json','Elastic Security SIEM alert',
  [F.ts,F.severity,F.src_ip,F.user,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('rule_type',['query','threshold','eql','ml','indicator_match'],[0.25,0.2,0.2,0.2,0.15]),F.risk]);

add('wazuh-vulnerability','wazuh:vuln','Wazuh','Vulnerability','json','Wazuh vulnerability detection event',
  [F.ts,F.hostname,F.severity,F.status],{},
  [intF('cvss_score',0,10),enumF('package_type',['deb','rpm','npm','pip','windows_update'],[0.2,0.2,0.2,0.2,0.2])]);

add('crowdsec-alert','crowdsec:alert','CrowdSec','CrowdSec','json','CrowdSec community IDS alert',
  [F.ts,F.src_ip,F.severity],
  {src_ip:'src_ip'},
  [enumF('scenario',['ssh-bf','http-bf','http-crawl','http-sqli','http-xss'],[0.2,0.2,0.2,0.2,0.2]),enumF('decision',['ban','captcha','throttle'],[0.5,0.3,0.2])]);

add('fail2ban-event','fail2ban:event','Fail2ban','Fail2ban','json','Fail2ban intrusion prevention event',
  [F.ts,F.src_ip,F.status],
  {src_ip:'src_ip'},
  [enumF('action',['Ban','Unban','Found','Already_banned'],[0.3,0.25,0.3,0.15]),enumF('jail',['sshd','nginx-http-auth','apache-auth','postfix'],[0.35,0.25,0.2,0.2])]);

add('wireguard-peer','wireguard:peer','WireGuard','VPN Peer','json','WireGuard VPN peer event',
  [F.ts,F.src_ip,F.status],
  {src_ip:'src_ip'},
  [enumF('event_type',['handshake','keepalive','peer_added','peer_removed'],[0.35,0.3,0.2,0.15]),F.bytes]);

add('nebula-event','nebula:event','Slack','Nebula','json','Nebula mesh VPN event',
  [F.ts,F.src_ip,F.hostname,F.status],
  {src_ip:'src_ip'},
  [enumF('event_type',['handshake','tunnel_established','tunnel_closed','lighthouse_update'],[0.3,0.25,0.25,0.2])]);

add('headscale-event','headscale:event','Headscale','Coordination','json','Headscale coordination server event',
  [F.ts,F.user,F.src_ip,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('event_type',['node_registered','node_expired','preauth_key_created','route_enabled'],[0.3,0.2,0.25,0.25])]);

add('boundary-session','boundary:session','HashiCorp','Boundary','json','HashiCorp Boundary session event',
  [F.ts,F.user,F.src_ip,F.status,F.duration],
  {src_ip:'src_ip',user:'user'},
  [enumF('target_type',['tcp','ssh','http','postgres','rdp'],[0.2,0.25,0.2,0.2,0.15])]);

add('consul-audit','consul:audit','HashiCorp','Consul','json','HashiCorp Consul audit log',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('resource',['kv','service','node','session','acl','intention'],[0.2,0.2,0.15,0.15,0.15,0.15])]);

add('vault-secrets','vault:secret','HashiCorp','Vault','json','HashiCorp Vault secret access log',
  [F.ts,F.user,F.src_ip,F.action,F.status],
  {src_ip:'src_ip',user:'user'},
  [enumF('mount_type',['kv','transit','pki','aws','database','ssh'],[0.25,0.15,0.15,0.15,0.15,0.15])]);

add('packer-event','packer:event','HashiCorp','Packer','json','HashiCorp Packer build event',
  [F.ts,F.user,F.status,F.duration],
  {user:'user'},
  [enumF('builder',['amazon-ebs','azure-arm','googlecompute','docker','vmware-iso'],[0.25,0.2,0.2,0.2,0.15])]);

add('waypoint-event','waypoint:event','HashiCorp','Waypoint','json','HashiCorp Waypoint deployment event',
  [F.ts,F.user,F.status],
  {user:'user'},
  [enumF('operation',['build','deploy','release','destroy','exec'],[0.2,0.25,0.25,0.15,0.15])]);

add('cni-event','cni:event','CNI','Kubernetes','json','Kubernetes CNI network plugin event',
  [F.ts,F.hostname,F.status],{},
  [enumF('plugin',['calico','cilium','flannel','weave','multus'],[0.25,0.25,0.2,0.15,0.15]),enumF('event',['add','del','check','version'],[0.3,0.3,0.25,0.15])]);

add('cilium-event','cilium:event','Isovalent','Cilium','json','Cilium eBPF networking event',
  [F.ts,F.src_ip,F.dst_ip,F.action,F.status],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('type',['policy_verdict','drop','trace','l7','debug'],[0.3,0.2,0.2,0.2,0.1])]);

add('calico-event','calico:event','Tigera','Calico','json','Calico network policy event',
  [F.ts,F.src_ip,F.dst_ip,F.action],
  {src_ip:'src_ip',dst_ip:'dst_ip'},
  [enumF('policy_type',['globalnetworkpolicy','networkpolicy','profile','tier'],[0.3,0.3,0.2,0.2])]);

add('coredns-cache','coredns:cache','CoreDNS','Cache','json','CoreDNS cache statistics event',
  [F.ts,F.hostname],{},
  [intF('cache_hits',0,100000),intF('cache_misses',0,50000),enumF('zone',['cluster.local','in-addr.arpa','ip6.arpa','.'],[0.3,0.25,0.25,0.2])]);

add('metallb-event','metallb:event','MetalLB','Load Balancer','json','MetalLB Kubernetes LB event',
  [F.ts,F.hostname,F.status],{},
  [enumF('event_type',['ip_assigned','ip_released','bgp_session','layer2_announce'],[0.3,0.2,0.25,0.25])]);

// ═══════════════════════════════════════════════════════════════════════════════
// Done defining. Now build and write files.
// ═══════════════════════════════════════════════════════════════════════════════

console.log(`\n=== Bulk Definition Generator ===`);
console.log(`Definitions directory: ${DEFINITIONS_DIR}`);
console.log(`Existing files: ${existingFiles.size}`);
console.log(`Definitions to generate: ${BULK.length}`);

let created = 0;
let skipped = 0;
const newEntries = []; // for index.js

for (const item of BULK) {
  const filename = item.filename + '.json';

  // Skip if already exists
  if (existingFiles.has(filename)) {
    skipped++;
    continue;
  }

  const def = makeDef(
    item.sourcetype,
    item.vendor,
    item.product,
    item.format,
    item.description,
    item.fields,
    item.hints,
    item.extra
  );

  const json = JSON.stringify(def);
  const filePath = path.join(DEFINITIONS_DIR, filename);
  fs.writeFileSync(filePath, json, 'utf8');
  created++;

  // Collect index entries
  newEntries.push({ sourcetype: item.sourcetype, filename, slug: item.filename });
}

console.log(`\nCreated: ${created} new definitions`);
console.log(`Skipped: ${skipped} (already exist)`);

// ── Rebuild index.js from all JSON files ─────────────────────────────────────
console.log(`\nRebuilding index.js SOURCETYPE_MAP from all JSON files...`);

// Read all JSON files and build entries
const allFiles = fs.readdirSync(DEFINITIONS_DIR).filter(f => f.endsWith('.json')).sort();
const mapEntries = [];
for (const file of allFiles) {
  try {
    const raw = fs.readFileSync(path.join(DEFINITIONS_DIR, file), 'utf8');
    const def = JSON.parse(raw);
    if (def.sourcetype) {
      const st = def.sourcetype;
      const slug = file.replace('.json', '');
      mapEntries.push([st, file]);
      if (slug !== st) mapEntries.push([slug, file]);
    }
  } catch (_) { /* skip */ }
}
mapEntries.sort((a, b) => a[0].localeCompare(b[0]));

// Read existing index.js to preserve the functions section
let indexContent = fs.readFileSync(INDEX_FILE, 'utf8');
const fnStart = indexContent.indexOf('const DEFINITIONS_DIR');
const functionsSection = indexContent.slice(fnStart);

const mapLines = mapEntries.map(([st, file]) => {
  const key = "'" + st + "'";
  return '  ' + key.padEnd(40) + ": '" + file + "',";
});

indexContent = `'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Sourcetype-to-filename mapping.
 * Maps sourcetype identifiers used in scenarios/CLI to their
 * corresponding definition JSON files on disk.
 * Auto-generated: ${allFiles.length} definitions, ${mapEntries.length} map entries.
 */
const SOURCETYPE_MAP = {
${mapLines.join('\n')}
};

${functionsSection}`;

fs.writeFileSync(INDEX_FILE, indexContent, 'utf8');

// ── Final stats ─────────────────────────────────────────────────────────────
const totalFiles = fs.readdirSync(DEFINITIONS_DIR).filter(f => f.endsWith('.json')).length;
const totalSize = fs.readdirSync(DEFINITIONS_DIR)
  .filter(f => f.endsWith('.json'))
  .reduce((sum, f) => sum + fs.statSync(path.join(DEFINITIONS_DIR, f)).size, 0);

console.log(`\n=== Final Results ===`);
console.log(`Total definition files: ${totalFiles}`);
console.log(`Total disk usage: ${(totalSize / 1024 / 1024).toFixed(2)} MB`);
console.log(`Average file size: ${Math.round(totalSize / totalFiles)} bytes`);
console.log(`index.js updated with ${newEntries.length} new sourcetype entries`);
console.log(`\nDone!`);
