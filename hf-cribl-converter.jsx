import React, { useState, useCallback, useMemo, useRef, useEffect } from "react";

// ─────────────────────────────────────────────
// Theme Tokens
// ─────────────────────────────────────────────
const T = {
  bg: "#06060b",
  bgGrad: "radial-gradient(ellipse at 50% 0%, #12121e 0%, #06060b 70%)",
  surface: "rgba(255,255,255,.03)",
  surfaceHover: "rgba(255,255,255,.055)",
  surfaceSolid: "#0e0e16",
  glass: "rgba(255,255,255,.04)",
  glassBorder: "rgba(255,255,255,.07)",
  border: "rgba(255,255,255,.06)",
  borderHover: "rgba(255,255,255,.12)",
  accent: "#6366f1",
  accentLight: "#818cf8",
  accentDim: "#4f46e5",
  accentGlow: "rgba(99,102,241,.10)",
  accentGlowStrong: "rgba(99,102,241,.20)",
  teal: "#2dd4bf",
  tealGlow: "rgba(45,212,191,.10)",
  amber: "#fbbf24",
  amberGlow: "rgba(251,191,36,.10)",
  green: "#34d399",
  greenGlow: "rgba(52,211,153,.10)",
  red: "#f87171",
  redGlow: "rgba(248,113,113,.08)",
  blue: "#60a5fa",
  blueGlow: "rgba(96,165,250,.10)",
  purple: "#a78bfa",
  purpleGlow: "rgba(167,139,250,.10)",
  cyan: "#22d3ee",
  cyanGlow: "rgba(34,211,238,.10)",
  text: "#f0f0f5",
  textSec: "#a1a1b5",
  textMuted: "#55556a",
  mono: "'DM Mono', 'JetBrains Mono', 'Fira Code', monospace",
  sans: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
  display: "'Syne', 'Inter', sans-serif",
  radius: 12,
  radiusSm: 8,
  radiusLg: 16,
  shadow: "0 1px 3px rgba(0,0,0,.4), 0 8px 24px rgba(0,0,0,.3)",
  shadowLg: "0 4px 12px rgba(0,0,0,.5), 0 16px 48px rgba(0,0,0,.4)",
};

// ─────────────────────────────────────────────
// SVG Icons (inline for zero deps)
// ─────────────────────────────────────────────
const Icon = {
  upload: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="17 8 12 3 7 8" /><line x1="12" y1="3" x2="12" y2="15" />
    </svg>
  ),
  github: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
    </svg>
  ),
  analyze: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="20" x2="18" y2="10" /><line x1="12" y1="20" x2="12" y2="4" /><line x1="6" y1="20" x2="6" y2="14" />
    </svg>
  ),
  code: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" />
    </svg>
  ),
  download: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" />
    </svg>
  ),
  lab: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 3h6v6l4.5 7.5a2 2 0 0 1-1.7 3H6.2a2 2 0 0 1-1.7-3L9 9V3z" /><path d="M10 3h4" />
    </svg>
  ),
  copy: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
  ),
  check: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  ),
  arrow: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="5" y1="12" x2="19" y2="12" /><polyline points="12 5 19 12 12 19" />
    </svg>
  ),
  warn: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  ),
  file: (
    <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /><polyline points="10 9 9 9 8 9" />
    </svg>
  ),
  stream: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" />
    </svg>
  ),
};

// ─────────────────────────────────────────────
// Copy-to-clipboard hook
// ─────────────────────────────────────────────
function useCopy() {
  const [copied, setCopied] = useState(false);
  const copy = useCallback((text) => {
    navigator.clipboard?.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, []);
  return { copied, copy };
}

function CopyBtn({ text, label = "Copy", style: overrides }) {
  const { copied, copy } = useCopy();
  return (
    <button
      style={{ ...styles.btnGhost, ...overrides }}
      onClick={() => copy(text)}
    >
      {copied ? Icon.check : Icon.copy}
      <span>{copied ? "Copied" : label}</span>
    </button>
  );
}

// ─────────────────────────────────────────────
// Splunk -> Cribl Conversion Engine
// ─────────────────────────────────────────────

function parseINI(text) {
  const stanzas = {};
  let current = null;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const stanzaMatch = line.match(/^\[([^\]]+)\]$/);
    if (stanzaMatch) {
      current = stanzaMatch[1];
      if (!stanzas[current]) stanzas[current] = {};
      continue;
    }
    if (current) {
      const eqIdx = line.indexOf("=");
      if (eqIdx > 0) {
        const key = line.slice(0, eqIdx).trim();
        const val = line.slice(eqIdx + 1).trim();
        stanzas[current][key] = val;
      }
    }
  }
  return stanzas;
}

function convertSedCmd(name, expr) {
  const parts = expr.match(/s\/([^/]*)\/([^/]*)\/(g?)/);
  if (!parts) return null;
  return {
    id: `sed_${name}`,
    filter: "true",
    conf: { find: parts[1], replace: parts[2] || "", global: parts[3] === "g" },
    description: `SEDCMD: ${name} — s/${parts[1]}/${parts[2]}/${parts[3] || ""}`,
    groupId: "splunk_sed",
    type: "Sed",
  };
}

function convertExtract(name, regex) {
  return {
    id: `extract_${name}`,
    filter: "true",
    conf: { regex, regexList: [{ regex, fieldName: "" }], overwrite: false },
    description: `EXTRACT: ${name}`,
    groupId: "splunk_extract",
    type: "Regex Extract",
  };
}

function convertTimestamp(format, prefix) {
  const conf = { type: "auto" };
  if (format) conf.strptime = format;
  if (prefix) conf.prefix = prefix;
  return {
    id: "auto_timestamp",
    filter: "true",
    conf,
    description: `Timestamp — format: ${format || "auto"}, prefix: ${prefix || "none"}`,
    groupId: "splunk_time",
    type: "Auto Timestamp",
  };
}

function convertLineBreaker(regex) {
  return {
    id: "event_breaker",
    filter: "true",
    conf: { regex },
    description: `LINE_BREAKER → Event Breaker: ${regex}`,
    groupId: "splunk_linebreak",
    type: "Event Breaker",
  };
}

function convertTransform(name, transform) {
  const { REGEX, FORMAT, DEST_KEY, SOURCE_KEY, DELIMS, FIELDS, MV_ADD, LOOKUP } = transform;

  if (LOOKUP) {
    return {
      id: `lookup_${name}`, filter: "true",
      conf: { file: LOOKUP, matchMode: "exact", reloadPeriodSec: 60 },
      description: `LOOKUP: ${name} → ${LOOKUP}`, groupId: "splunk_lookup", type: "Lookup",
    };
  }
  if (DELIMS) {
    const delimParts = DELIMS.replace(/"/g, "").split(",");
    return {
      id: `delim_extract_${name}`, filter: "true",
      conf: { type: "delim", delimChar: delimParts[0] || ",", quoteChar: delimParts[1] || '"', fields: FIELDS ? FIELDS.split(",").map((f) => f.trim()) : [] },
      description: `Delimited extract: ${name}`, groupId: "splunk_delim", type: "Parser",
    };
  }
  if (REGEX) {
    const fn = {
      id: `regex_${name}`, filter: "true",
      conf: { regex: REGEX, regexList: [{ regex: REGEX, fieldName: FORMAT || "" }], overwrite: false },
      description: `TRANSFORMS: ${name}`, groupId: "splunk_transforms", type: "Regex Extract",
    };
    if (SOURCE_KEY) fn.conf.source = SOURCE_KEY;
    if (DEST_KEY && DEST_KEY === "_raw") {
      fn.type = "Sed";
      fn.conf = { find: REGEX, replace: FORMAT || "" };
      fn.description += " (writes _raw → Sed)";
    }
    if (MV_ADD === "true") fn.conf.overwrite = false;
    return fn;
  }
  return {
    id: `eval_${name}`, filter: "true",
    conf: { add: Object.entries(transform).map(([k, v]) => ({ name: k, value: `'${v}'` })) },
    description: `Eval passthrough: ${name}`, groupId: "splunk_eval", type: "Eval",
  };
}

function buildPipeline(propsText, transformsText) {
  const props = parseINI(propsText);
  const transforms = parseINI(transformsText);
  const functions = [];
  const warnings = [];
  const stats = { sed: 0, extract: 0, timestamp: 0, linebreak: 0, transforms: 0, lookup: 0, other: 0 };

  for (const [stanza, directives] of Object.entries(props)) {
    for (const [key, value] of Object.entries(directives)) {
      const upper = key.toUpperCase();
      if (key.startsWith("SEDCMD-")) {
        const fn = convertSedCmd(key.replace("SEDCMD-", ""), value);
        if (fn) { functions.push(fn); stats.sed++; }
        else warnings.push(`Could not parse SEDCMD in [${stanza}]: ${value}`);
      } else if (key.startsWith("EXTRACT-")) {
        functions.push(convertExtract(key.replace("EXTRACT-", ""), value));
        stats.extract++;
      } else if (upper === "TIME_FORMAT" || upper === "TIME_PREFIX") {
        if (!functions.find((f) => f.id === "auto_timestamp")) {
          functions.push(convertTimestamp(directives["TIME_FORMAT"] || directives["time_format"], directives["TIME_PREFIX"] || directives["time_prefix"]));
          stats.timestamp++;
        }
      } else if (upper === "LINE_BREAKER") {
        functions.push(convertLineBreaker(value));
        stats.linebreak++;
      } else if (key.startsWith("TRANSFORMS-") || key.startsWith("REPORT-")) {
        for (const ref of value.split(",").map((s) => s.trim())) {
          if (transforms[ref]) { functions.push(convertTransform(ref, transforms[ref])); stats.transforms++; }
          else warnings.push(`Transform [${ref}] referenced in [${stanza}] not found in transforms.conf`);
        }
      } else if (upper === "LOOKUP") {
        functions.push({ id: `lookup_${stanza}`, filter: "true", conf: { file: value, matchMode: "exact" }, description: `Lookup: ${value}`, groupId: "splunk_lookup", type: "Lookup" });
        stats.lookup++;
      } else if (!["SHOULD_LINEMERGE", "TRUNCATE", "MAX_TIMESTAMP_LOOKAHEAD", "TZ", "CHARSET"].includes(upper)) {
        stats.other++;
      }
    }
  }
  for (const [name, transform] of Object.entries(transforms)) {
    if (!functions.find((f) => f.id.includes(name))) {
      functions.push(convertTransform(name, transform));
      stats.transforms++;
    }
  }
  return {
    pipeline: {
      id: "splunk_hf_converted",
      conf: { asyncFuncTimeout: 1000, output: "default", functions },
      description: "Converted from Splunk Heavy Forwarder props.conf / transforms.conf",
    },
    warnings, stats, functionCount: functions.length,
  };
}

// ─────────────────────────────────────────────
// Global CSS
// ─────────────────────────────────────────────
const fontLink = "https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Inter:wght@400;500;600;700&family=Syne:wght@400;600;700;800&display=swap";

const globalCSS = `
  @import url('${fontLink}');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html { scroll-behavior: smooth; }
  body { background: ${T.bg}; color: ${T.text}; font-family: ${T.sans}; -webkit-font-smoothing: antialiased; }
  ::-webkit-scrollbar { width: 5px; height: 5px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: rgba(255,255,255,.08); border-radius: 10px; }
  ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,.14); }
  ::selection { background: ${T.accent}; color: #fff; }

  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  @keyframes pulse {
    0%, 100% { opacity: .6; }
    50%      { opacity: 1; }
  }
  @keyframes shimmer {
    0%   { background-position: -200% 0; }
    100% { background-position: 200% 0; }
  }
  .fade-up { animation: fadeUp .35s ease-out both; }
  .card-hover { transition: border-color .2s, box-shadow .2s, transform .15s; }
  .card-hover:hover { border-color: ${T.borderHover}; box-shadow: ${T.shadow}; transform: translateY(-1px); }
`;

// ─────────────────────────────────────────────
// Styles
// ─────────────────────────────────────────────
const styles = {
  app: {
    minHeight: "100vh",
    background: T.bgGrad,
    color: T.text,
    fontFamily: T.sans,
    display: "flex",
    flexDirection: "column",
  },
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "0 32px",
    height: 64,
    borderBottom: `1px solid ${T.border}`,
    background: "rgba(6,6,11,.85)",
    backdropFilter: "blur(16px)",
    WebkitBackdropFilter: "blur(16px)",
    position: "sticky",
    top: 0,
    zIndex: 100,
  },
  logoWrap: {
    display: "flex",
    alignItems: "center",
    gap: 12,
  },
  logoIcon: {
    width: 32,
    height: 32,
    borderRadius: 8,
    background: `linear-gradient(135deg, ${T.accent}, ${T.teal})`,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    color: "#fff",
    flexShrink: 0,
  },
  logoText: {
    fontFamily: T.display,
    fontSize: 17,
    fontWeight: 700,
    color: T.text,
    letterSpacing: "-0.01em",
  },
  logoSub: {
    fontSize: 12,
    color: T.textMuted,
    fontFamily: T.mono,
    letterSpacing: "0.02em",
  },
  version: {
    fontSize: 11,
    padding: "3px 10px",
    borderRadius: 999,
    background: T.glass,
    border: `1px solid ${T.glassBorder}`,
    color: T.textSec,
    fontFamily: T.mono,
  },
  nav: {
    display: "flex",
    gap: 2,
    borderBottom: `1px solid ${T.border}`,
    background: "rgba(6,6,11,.6)",
    backdropFilter: "blur(12px)",
    WebkitBackdropFilter: "blur(12px)",
    padding: "0 28px",
    overflowX: "auto",
  },
  tab: (active) => ({
    padding: "14px 18px",
    cursor: "pointer",
    fontSize: 13,
    fontWeight: active ? 600 : 400,
    color: active ? T.text : T.textMuted,
    background: "transparent",
    borderBottom: active ? `2px solid ${T.accent}` : "2px solid transparent",
    transition: "all .2s ease",
    whiteSpace: "nowrap",
    userSelect: "none",
    display: "flex",
    alignItems: "center",
    gap: 8,
    position: "relative",
  }),
  tabDot: {
    width: 5,
    height: 5,
    borderRadius: "50%",
    background: T.accent,
  },
  main: {
    flex: 1,
    padding: "28px 32px",
    maxWidth: 1360,
    width: "100%",
    margin: "0 auto",
  },
  card: {
    background: T.glass,
    border: `1px solid ${T.glassBorder}`,
    borderRadius: T.radiusLg,
    padding: 28,
    marginBottom: 20,
    backdropFilter: "blur(8px)",
    WebkitBackdropFilter: "blur(8px)",
  },
  h2: {
    fontFamily: T.display,
    fontSize: 20,
    fontWeight: 700,
    color: T.text,
    marginBottom: 8,
    letterSpacing: "-0.01em",
  },
  h3: {
    fontSize: 11,
    fontWeight: 600,
    color: T.textMuted,
    textTransform: "uppercase",
    letterSpacing: "0.08em",
    marginBottom: 12,
  },
  subtitle: {
    fontSize: 14,
    color: T.textSec,
    lineHeight: 1.6,
    marginBottom: 24,
  },
  textarea: {
    width: "100%",
    minHeight: 280,
    background: "rgba(0,0,0,.3)",
    color: T.text,
    border: `1px solid ${T.border}`,
    borderRadius: T.radius,
    padding: 16,
    fontFamily: T.mono,
    fontSize: 12.5,
    lineHeight: 1.7,
    resize: "vertical",
    outline: "none",
    transition: "border-color .2s",
  },
  btnPrimary: {
    padding: "10px 24px",
    fontSize: 13,
    fontWeight: 600,
    fontFamily: T.sans,
    borderRadius: T.radiusSm,
    border: "none",
    background: `linear-gradient(135deg, ${T.accent}, ${T.accentDim})`,
    color: "#fff",
    cursor: "pointer",
    transition: "all .2s ease",
    display: "inline-flex",
    alignItems: "center",
    gap: 8,
    boxShadow: `0 2px 8px rgba(99,102,241,.3)`,
  },
  btnGhost: {
    padding: "8px 16px",
    fontSize: 12,
    fontWeight: 500,
    fontFamily: T.sans,
    borderRadius: T.radiusSm,
    border: `1px solid ${T.border}`,
    background: "transparent",
    color: T.textSec,
    cursor: "pointer",
    transition: "all .2s ease",
    display: "inline-flex",
    alignItems: "center",
    gap: 6,
  },
  btnOutline: {
    padding: "10px 20px",
    fontSize: 13,
    fontWeight: 500,
    fontFamily: T.sans,
    borderRadius: T.radiusSm,
    border: `1px solid ${T.border}`,
    background: T.glass,
    color: T.text,
    cursor: "pointer",
    transition: "all .2s ease",
    display: "inline-flex",
    alignItems: "center",
    gap: 8,
  },
  input: {
    width: "100%",
    padding: "10px 14px",
    background: "rgba(0,0,0,.3)",
    color: T.text,
    border: `1px solid ${T.border}`,
    borderRadius: T.radiusSm,
    fontFamily: T.sans,
    fontSize: 13,
    outline: "none",
    transition: "border-color .2s",
  },
  label: {
    fontSize: 12,
    fontWeight: 500,
    color: T.textSec,
    marginBottom: 6,
    display: "block",
  },
  pill: (color) => ({
    display: "inline-flex",
    alignItems: "center",
    fontSize: 11,
    fontWeight: 600,
    padding: "3px 10px",
    borderRadius: 999,
    background: `${color}14`,
    color,
    border: `1px solid ${color}28`,
    fontFamily: T.mono,
    letterSpacing: "0.02em",
  }),
  pre: {
    background: "rgba(0,0,0,.4)",
    border: `1px solid ${T.border}`,
    borderRadius: T.radius,
    padding: 20,
    fontFamily: T.mono,
    fontSize: 12,
    lineHeight: 1.8,
    color: T.text,
    overflow: "auto",
    maxHeight: 520,
    whiteSpace: "pre-wrap",
    wordBreak: "break-word",
  },
  row: { display: "flex", gap: 16, flexWrap: "wrap" },
  col: { flex: 1, minWidth: 280 },
  stat: {
    textAlign: "center",
    padding: "20px 16px",
    background: T.glass,
    borderRadius: T.radius,
    border: `1px solid ${T.glassBorder}`,
    transition: "all .2s ease",
  },
  statNum: {
    fontFamily: T.display,
    fontSize: 32,
    fontWeight: 800,
    letterSpacing: "-0.02em",
    lineHeight: 1,
  },
  statLabel: {
    fontSize: 11,
    color: T.textMuted,
    marginTop: 6,
    fontWeight: 500,
    textTransform: "uppercase",
    letterSpacing: "0.05em",
  },
  warning: {
    padding: "10px 14px",
    background: T.redGlow,
    border: `1px solid rgba(248,113,113,.15)`,
    borderRadius: T.radiusSm,
    color: T.red,
    fontSize: 12,
    marginBottom: 8,
    display: "flex",
    alignItems: "flex-start",
    gap: 8,
    lineHeight: 1.5,
  },
  fnCard: {
    padding: "14px 18px",
    background: T.glass,
    border: `1px solid ${T.glassBorder}`,
    borderRadius: T.radius,
    marginBottom: 8,
    transition: "all .15s ease",
  },
  fnType: (color) => ({
    fontSize: 10,
    fontWeight: 700,
    color,
    textTransform: "uppercase",
    letterSpacing: "0.06em",
    fontFamily: T.mono,
  }),
  fnDesc: {
    fontSize: 12,
    color: T.textSec,
    lineHeight: 1.5,
  },
  emptyState: {
    textAlign: "center",
    padding: "80px 24px",
    color: T.textMuted,
  },
  emptyIcon: {
    width: 56,
    height: 56,
    borderRadius: 16,
    background: T.glass,
    border: `1px solid ${T.glassBorder}`,
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    marginBottom: 16,
    color: T.textMuted,
  },
  dropZone: (active) => ({
    border: `2px dashed ${active ? T.accent : T.border}`,
    borderRadius: T.radiusLg,
    padding: "56px 24px",
    textAlign: "center",
    cursor: "pointer",
    background: active ? T.accentGlow : "transparent",
    transition: "all .25s ease",
  }),
  grid2: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 },
  grid4: { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))", gap: 12 },
};

// Fn type -> color mapping
const fnColor = (type) => {
  const map = { "Sed": T.cyan, "Regex Extract": T.green, "Auto Timestamp": T.blue, "Event Breaker": T.amber, "Lookup": T.purple, "Parser": T.teal, "Eval": T.accent };
  return map[type] || T.textSec;
};

// ─────────────────────────────────────────────
// Sample Data
// ─────────────────────────────────────────────
const SAMPLE_PROPS = `[syslog]
TIME_FORMAT = %b %d %H:%M:%S
TIME_PREFIX = ^
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\\r\\n]+)
SEDCMD-clean_newlines = s/\\\\n/ /g
SEDCMD-strip_ansi = s/\\x1b\\[[0-9;]*m//g
EXTRACT-src_ip = src=(?<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)
EXTRACT-dest_ip = dest=(?<dest_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)
TRANSFORMS-lookup = ip_to_host
REPORT-extract_fields = kv_extract

[access_combined]
TIME_FORMAT = %d/%b/%Y:%H:%M:%S %z
EXTRACT-http_method = (?<http_method>GET|POST|PUT|DELETE|PATCH)
TRANSFORMS-mask = mask_credit_card
SEDCMD-remove_query = s/\\?[^ ]*//g`;

const SAMPLE_TRANSFORMS = `[ip_to_host]
REGEX = src=(?<src_ip>[^ ]+)
FORMAT = src_host::$1.example.com
DEST_KEY = MetaData:Host

[kv_extract]
REGEX = ([\\w]+)=([^ ]+)
FORMAT = $1::$2

[mask_credit_card]
REGEX = \\b(\\d{4})\\d{8}(\\d{4})\\b
FORMAT = $1********$2
DEST_KEY = _raw
SOURCE_KEY = _raw`;

// ─────────────────────────────────────────────
// Tab: Upload
// ─────────────────────────────────────────────
function UploadTab({ onLoad }) {
  const [dragActive, setDragActive] = useState(false);
  const [files, setFiles] = useState({ props: null, transforms: null });
  const propsRef = useRef(null);
  const transRef = useRef(null);

  const handleFile = useCallback((file, type) => {
    const reader = new FileReader();
    reader.onload = (e) => setFiles((prev) => ({ ...prev, [type]: { name: file.name, content: e.target.result } }));
    reader.readAsText(file);
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragActive(false);
    for (const file of e.dataTransfer.files) {
      if (file.name.includes("props")) handleFile(file, "props");
      else if (file.name.includes("transforms")) handleFile(file, "transforms");
      else handleFile(file, "props");
    }
  }, [handleFile]);

  return (
    <div className="fade-up">
      <div style={styles.card}>
        <h2 style={styles.h2}>Upload Configuration Files</h2>
        <p style={styles.subtitle}>
          Drop your Splunk Heavy Forwarder <code style={{ color: T.accent, fontFamily: T.mono, fontSize: 13 }}>props.conf</code> and{" "}
          <code style={{ color: T.accent, fontFamily: T.mono, fontSize: 13 }}>transforms.conf</code> to convert them into Cribl Stream pipelines.
        </p>

        <div
          style={styles.dropZone(dragActive)}
          onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
          onDragLeave={() => setDragActive(false)}
          onDrop={handleDrop}
          onClick={() => propsRef.current?.click()}
        >
          <div style={{ color: dragActive ? T.accent : T.textMuted, marginBottom: 16, transition: "color .2s" }}>{Icon.file}</div>
          <div style={{ color: T.textSec, fontSize: 15, fontWeight: 500, marginBottom: 6 }}>
            Drag &amp; drop .conf files here
          </div>
          <div style={{ color: T.textMuted, fontSize: 13 }}>
            or click to browse your filesystem
          </div>
        </div>

        <input ref={propsRef} type="file" accept=".conf,.txt" style={{ display: "none" }} onChange={(e) => e.target.files[0] && handleFile(e.target.files[0], "props")} />
        <input ref={transRef} type="file" accept=".conf,.txt" style={{ display: "none" }} onChange={(e) => e.target.files[0] && handleFile(e.target.files[0], "transforms")} />

        <div style={{ display: "flex", gap: 12, marginTop: 20 }}>
          <button
            style={{ ...styles.btnOutline, flex: 1, justifyContent: "center" }}
            onClick={() => propsRef.current?.click()}
          >
            {files.props ? <span style={{ color: T.green }}>&#10003; {files.props.name}</span> : "Select props.conf"}
          </button>
          <button
            style={{ ...styles.btnOutline, flex: 1, justifyContent: "center" }}
            onClick={() => transRef.current?.click()}
          >
            {files.transforms ? <span style={{ color: T.green }}>&#10003; {files.transforms.name}</span> : "Select transforms.conf"}
          </button>
        </div>

        {(files.props || files.transforms) && (
          <div style={{ marginTop: 20 }}>
            <button style={styles.btnPrimary} onClick={() => onLoad(files.props?.content || "", files.transforms?.content || "")}>
              Convert to Pipeline {Icon.arrow}
            </button>
          </div>
        )}
      </div>

      <div style={styles.card}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
          <div style={{ width: 36, height: 36, borderRadius: 10, background: T.accentGlow, border: `1px solid ${T.accent}22`, display: "flex", alignItems: "center", justifyContent: "center", color: T.accent }}>
            {Icon.lab}
          </div>
          <div>
            <div style={{ fontSize: 14, fontWeight: 600 }}>Quick Start</div>
            <div style={{ fontSize: 12, color: T.textMuted }}>Load sample syslog and access_combined configs</div>
          </div>
        </div>
        <button style={styles.btnPrimary} onClick={() => onLoad(SAMPLE_PROPS, SAMPLE_TRANSFORMS)}>
          Load Sample Data {Icon.arrow}
        </button>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// Tab: GitHub
// ─────────────────────────────────────────────
function GitHubTab({ onLoad }) {
  const [repoUrl, setRepoUrl] = useState("");
  const [propsPath, setPropsPath] = useState("etc/system/local/props.conf");
  const [transPath, setTransPath] = useState("etc/system/local/transforms.conf");
  const [token, setToken] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const fetchFile = async (owner, repo, path, tok) => {
    const headers = { Accept: "application/vnd.github.v3.raw" };
    if (tok) headers.Authorization = `token ${tok}`;
    const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/contents/${path}`, { headers });
    if (!res.ok) throw new Error(`${path}: ${res.status} ${res.statusText}`);
    return res.text();
  };

  const handleFetch = async () => {
    setLoading(true);
    setError("");
    try {
      const match = repoUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
      if (!match) throw new Error("Invalid GitHub URL");
      const [, owner, repo] = match;
      const [propsContent, transContent] = await Promise.allSettled([
        fetchFile(owner, repo.replace(/\.git$/, ""), propsPath, token),
        fetchFile(owner, repo.replace(/\.git$/, ""), transPath, token),
      ]);
      onLoad(
        propsContent.status === "fulfilled" ? propsContent.value : "",
        transContent.status === "fulfilled" ? transContent.value : ""
      );
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fade-up" style={styles.card}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
        <div style={{ color: T.text }}>{Icon.github}</div>
        <h2 style={{ ...styles.h2, marginBottom: 0 }}>Fetch from GitHub</h2>
      </div>
      <p style={styles.subtitle}>
        Pull configuration files directly from a GitHub repository.
      </p>

      <div style={{ marginBottom: 16 }}>
        <label style={styles.label}>Repository URL</label>
        <input style={styles.input} placeholder="https://github.com/owner/repo" value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)} />
      </div>

      <div style={{ ...styles.row, marginBottom: 16 }}>
        <div style={styles.col}>
          <label style={styles.label}>props.conf path</label>
          <input style={styles.input} value={propsPath} onChange={(e) => setPropsPath(e.target.value)} />
        </div>
        <div style={styles.col}>
          <label style={styles.label}>transforms.conf path</label>
          <input style={styles.input} value={transPath} onChange={(e) => setTransPath(e.target.value)} />
        </div>
      </div>

      <div style={{ marginBottom: 20 }}>
        <label style={styles.label}>Personal Access Token <span style={{ color: T.textMuted, fontWeight: 400 }}>(optional, for private repos)</span></label>
        <input style={styles.input} type="password" placeholder="ghp_xxxxxxxxxxxx" value={token} onChange={(e) => setToken(e.target.value)} />
      </div>

      {error && <div style={styles.warning}>{Icon.warn} {error}</div>}

      <button style={styles.btnPrimary} onClick={handleFetch} disabled={loading || !repoUrl}>
        {loading ? "Fetching..." : "Fetch & Convert"} {Icon.arrow}
      </button>
    </div>
  );
}

// ─────────────────────────────────────────────
// Tab: Analyze
// ─────────────────────────────────────────────
function AnalyzeTab({ result }) {
  if (!result) {
    return (
      <div style={styles.emptyState} className="fade-up">
        <div style={styles.emptyIcon}>{Icon.analyze}</div>
        <div style={{ fontSize: 15, fontWeight: 500, marginBottom: 6 }}>No data to analyze</div>
        <div style={{ fontSize: 13, color: T.textMuted }}>Upload or fetch configuration files first.</div>
      </div>
    );
  }

  const { stats, warnings, functionCount } = result;

  const statItems = [
    { label: "Total Functions", value: functionCount, color: T.accent },
    { label: "Sed Commands", value: stats.sed, color: T.cyan },
    { label: "Regex Extracts", value: stats.extract, color: T.green },
    { label: "Transforms", value: stats.transforms, color: T.purple },
    { label: "Timestamp", value: stats.timestamp, color: T.blue },
    { label: "Line Breakers", value: stats.linebreak, color: T.amber },
  ];

  return (
    <div className="fade-up">
      <div style={styles.card}>
        <h2 style={styles.h2}>Conversion Analysis</h2>
        <p style={{ ...styles.subtitle, marginBottom: 20 }}>
          {functionCount} pipeline functions generated from your Splunk configuration.
        </p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(150px, 1fr))", gap: 10 }}>
          {statItems.map((item) => (
            <div key={item.label} style={styles.stat}>
              <div style={{ ...styles.statNum, color: item.color }}>{item.value}</div>
              <div style={styles.statLabel}>{item.label}</div>
            </div>
          ))}
        </div>
      </div>

      {warnings.length > 0 && (
        <div style={styles.card}>
          <h3 style={styles.h3}>Warnings ({warnings.length})</h3>
          {warnings.map((w, i) => (
            <div key={i} style={styles.warning}>{Icon.warn} <span>{w}</span></div>
          ))}
        </div>
      )}

      <div style={styles.card}>
        <h3 style={styles.h3}>Pipeline Functions</h3>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {result.pipeline.conf.functions.map((fn, i) => (
            <div key={i} style={styles.fnCard} className="card-hover">
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                <span style={styles.pill(fnColor(fn.type))}>{fn.type}</span>
                <span style={{ fontSize: 13, fontWeight: 500, fontFamily: T.mono }}>{fn.id}</span>
              </div>
              <div style={styles.fnDesc}>{fn.description}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// Tab: Generate
// ─────────────────────────────────────────────
function GenerateTab({ result }) {
  if (!result) {
    return (
      <div style={styles.emptyState} className="fade-up">
        <div style={styles.emptyIcon}>{Icon.code}</div>
        <div style={{ fontSize: 15, fontWeight: 500, marginBottom: 6 }}>No pipeline generated</div>
        <div style={{ fontSize: 13, color: T.textMuted }}>Upload or fetch configuration files first.</div>
      </div>
    );
  }

  const json = JSON.stringify(result.pipeline, null, 2);

  return (
    <div className="fade-up">
      <div style={styles.card}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
          <h2 style={{ ...styles.h2, marginBottom: 0 }}>Cribl Pipeline JSON</h2>
          <CopyBtn text={json} label="Copy All" />
        </div>
        <pre style={styles.pre}>{json}</pre>
      </div>

      <div style={styles.card}>
        <h3 style={styles.h3}>Individual Functions</h3>
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {result.pipeline.conf.functions.map((fn, i) => (
            <div key={i}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={styles.pill(fnColor(fn.type))}>{fn.type}</span>
                  <span style={{ fontSize: 12, fontFamily: T.mono, color: T.textSec }}>{fn.id}</span>
                </div>
                <CopyBtn text={JSON.stringify(fn, null, 2)} label="Copy" />
              </div>
              <pre style={{ ...styles.pre, maxHeight: 200 }}>{JSON.stringify(fn, null, 2)}</pre>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// Tab: Export
// ─────────────────────────────────────────────
function ExportTab({ result }) {
  if (!result) {
    return (
      <div style={styles.emptyState} className="fade-up">
        <div style={styles.emptyIcon}>{Icon.download}</div>
        <div style={{ fontSize: 15, fontWeight: 500, marginBottom: 6 }}>Nothing to export</div>
        <div style={{ fontSize: 13, color: T.textMuted }}>Upload or fetch configuration files first.</div>
      </div>
    );
  }

  const pipelineJson = JSON.stringify(result.pipeline, null, 2);

  const downloadFile = (content, filename) => {
    const blob = new Blob([content], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const criblBundle = { pipelines: { [result.pipeline.id]: { conf: result.pipeline.conf, description: result.pipeline.description } } };

  const exports = [
    { label: "Pipeline JSON", desc: "Standard Cribl pipeline configuration", icon: Icon.code, color: T.accent, action: () => downloadFile(pipelineJson, "pipeline.json") },
    { label: "Cribl Bundle", desc: "Import-ready bundle for Cribl Stream", icon: Icon.download, color: T.teal, action: () => downloadFile(JSON.stringify(criblBundle, null, 2), "cribl-bundle.json") },
    { label: "Functions Only", desc: "Array of pipeline functions", icon: Icon.stream, color: T.purple, action: () => downloadFile(JSON.stringify(result.pipeline.conf.functions, null, 2), "functions.json") },
    { label: "Analysis Report", desc: "Conversion summary with warnings", icon: Icon.analyze, color: T.amber, action: () => downloadFile(JSON.stringify({ stats: result.stats, warnings: result.warnings, functionCount: result.functionCount }, null, 2), "analysis.json") },
  ];

  return (
    <div className="fade-up">
      <div style={styles.card}>
        <h2 style={styles.h2}>Export Pipeline</h2>
        <p style={styles.subtitle}>Download your converted pipeline in different formats.</p>
        <div style={styles.grid4}>
          {exports.map((item) => (
            <div
              key={item.label}
              className="card-hover"
              style={{ ...styles.fnCard, cursor: "pointer", padding: "20px 18px" }}
              onClick={item.action}
            >
              <div style={{ width: 36, height: 36, borderRadius: 10, background: `${item.color}14`, border: `1px solid ${item.color}22`, display: "flex", alignItems: "center", justifyContent: "center", color: item.color, marginBottom: 14 }}>
                {item.icon}
              </div>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 4 }}>{item.label}</div>
              <div style={{ fontSize: 12, color: T.textMuted, lineHeight: 1.5 }}>{item.desc}</div>
            </div>
          ))}
        </div>
      </div>

      <div style={styles.card}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div>
            <h3 style={{ ...styles.h3, marginBottom: 4 }}>Clipboard</h3>
            <div style={{ fontSize: 12, color: T.textMuted }}>Copy the full pipeline JSON directly.</div>
          </div>
          <CopyBtn text={pipelineJson} label="Copy Pipeline JSON" style={styles.btnPrimary} />
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// Tab: Stanza Lab
// ─────────────────────────────────────────────
function StanzaLabTab() {
  const [propsText, setPropsText] = useState(SAMPLE_PROPS);
  const [transText, setTransText] = useState(SAMPLE_TRANSFORMS);

  const result = useMemo(() => {
    try { return buildPipeline(propsText, transText); }
    catch { return null; }
  }, [propsText, transText]);

  const json = result ? JSON.stringify(result.pipeline.conf.functions, null, 2) : "// Enter valid conf to see output";

  return (
    <div className="fade-up">
      <div style={styles.card}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
          <div style={{ color: T.accent }}>{Icon.lab}</div>
          <h2 style={{ ...styles.h2, marginBottom: 0 }}>Stanza Lab</h2>
        </div>
        <p style={{ ...styles.subtitle, marginBottom: 0 }}>
          Edit props.conf and transforms.conf stanzas in real-time. Pipeline functions update live as you type.
        </p>
      </div>

      <div style={styles.grid2}>
        {/* Left: Editors */}
        <div>
          <div style={styles.card}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <div style={{ width: 8, height: 8, borderRadius: "50%", background: T.cyan }} />
                <span style={{ fontSize: 13, fontWeight: 600, fontFamily: T.mono }}>props.conf</span>
              </div>
              <span style={styles.pill(T.cyan)}>{Object.keys(parseINI(propsText)).length} stanzas</span>
            </div>
            <textarea
              style={{ ...styles.textarea, minHeight: 340 }}
              value={propsText}
              onChange={(e) => setPropsText(e.target.value)}
              spellCheck={false}
            />
          </div>

          <div style={styles.card}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <div style={{ width: 8, height: 8, borderRadius: "50%", background: T.purple }} />
                <span style={{ fontSize: 13, fontWeight: 600, fontFamily: T.mono }}>transforms.conf</span>
              </div>
              <span style={styles.pill(T.purple)}>{Object.keys(parseINI(transText)).length} stanzas</span>
            </div>
            <textarea
              style={{ ...styles.textarea, minHeight: 340 }}
              value={transText}
              onChange={(e) => setTransText(e.target.value)}
              spellCheck={false}
            />
          </div>
        </div>

        {/* Right: Output */}
        <div>
          <div style={styles.card}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <div style={{ width: 8, height: 8, borderRadius: "50%", background: T.green, animation: "pulse 2s ease-in-out infinite" }} />
                <span style={{ fontSize: 13, fontWeight: 600 }}>Pipeline Output</span>
              </div>
              {result && <span style={styles.pill(T.green)}>{result.functionCount} functions</span>}
            </div>
            <pre style={{ ...styles.pre, minHeight: 300, maxHeight: 520 }}>{json}</pre>
            <div style={{ marginTop: 14, display: "flex", gap: 8 }}>
              <CopyBtn text={json} label="Copy Functions" style={styles.btnPrimary} />
              <CopyBtn text={result ? JSON.stringify(result.pipeline, null, 2) : ""} label="Copy Full Pipeline" />
            </div>
          </div>

          {result && result.warnings.length > 0 && (
            <div style={styles.card}>
              <h3 style={styles.h3}>Warnings ({result.warnings.length})</h3>
              {result.warnings.map((w, i) => (
                <div key={i} style={styles.warning}>{Icon.warn} <span>{w}</span></div>
              ))}
            </div>
          )}

          {result && result.pipeline.conf.functions.length > 0 && (
            <div style={styles.card}>
              <h3 style={styles.h3}>Function Breakdown</h3>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {result.pipeline.conf.functions.map((fn, i) => (
                  <div key={i} style={{ ...styles.fnCard, padding: "10px 14px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
                      <span style={styles.pill(fnColor(fn.type))}>{fn.type}</span>
                      <span style={{ fontSize: 11, fontFamily: T.mono, color: T.textSec }}>{fn.id}</span>
                    </div>
                    <div style={{ ...styles.fnDesc, fontSize: 11 }}>{fn.description}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// Main App
// ─────────────────────────────────────────────

const TAB_CONFIG = [
  { id: "Upload", icon: Icon.upload },
  { id: "GitHub", icon: Icon.github },
  { id: "Analyze", icon: Icon.analyze },
  { id: "Generate", icon: Icon.code },
  { id: "Export", icon: Icon.download },
  { id: "Stanza Lab", icon: Icon.lab },
];

export default function HFCriblConverter() {
  const [activeTab, setActiveTab] = useState("Upload");
  const [result, setResult] = useState(null);

  const handleLoad = useCallback((props, transforms) => {
    const res = buildPipeline(props, transforms);
    setResult(res);
    setActiveTab("Analyze");
  }, []);

  useEffect(() => {
    const style = document.createElement("style");
    style.textContent = globalCSS;
    document.head.appendChild(style);
    return () => style.remove();
  }, []);

  const renderTab = () => {
    switch (activeTab) {
      case "Upload":    return <UploadTab onLoad={handleLoad} />;
      case "GitHub":    return <GitHubTab onLoad={handleLoad} />;
      case "Analyze":   return <AnalyzeTab result={result} />;
      case "Generate":  return <GenerateTab result={result} />;
      case "Export":    return <ExportTab result={result} />;
      case "Stanza Lab": return <StanzaLabTab />;
      default: return null;
    }
  };

  return (
    <div style={styles.app}>
      {/* Header */}
      <header style={styles.header}>
        <div style={styles.logoWrap}>
          <div style={styles.logoIcon}>{Icon.stream}</div>
          <div>
            <div style={styles.logoText}>HF Cribl Converter</div>
            <div style={styles.logoSub}>Splunk Heavy Forwarder → Cribl Stream</div>
          </div>
        </div>
        <span style={styles.version}>v1.0.0</span>
      </header>

      {/* Tabs */}
      <nav style={styles.nav}>
        {TAB_CONFIG.map(({ id, icon }) => (
          <div key={id} style={styles.tab(activeTab === id)} onClick={() => setActiveTab(id)}>
            <span style={{ display: "flex", opacity: activeTab === id ? 1 : 0.5 }}>{icon}</span>
            {id}
          </div>
        ))}
      </nav>

      {/* Content */}
      <main style={styles.main}>{renderTab()}</main>

      {/* Footer */}
      <footer style={{
        padding: "14px 32px",
        borderTop: `1px solid ${T.border}`,
        background: "rgba(6,6,11,.7)",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        fontSize: 11,
        color: T.textMuted,
        backdropFilter: "blur(8px)",
        WebkitBackdropFilter: "blur(8px)",
      }}>
        <span>Splunk HF → Cribl Stream Pipeline Converter</span>
        <span style={{ fontFamily: T.mono }}>Built for observability engineers</span>
      </footer>
    </div>
  );
}
