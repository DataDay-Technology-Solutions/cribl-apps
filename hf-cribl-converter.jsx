import React, { useState, useCallback, useMemo, useRef, useEffect } from "react";

// ─────────────────────────────────────────────
// DataDay Dark Theme Tokens
// ─────────────────────────────────────────────
const T = {
  bg: "#0a0a0f",
  surface: "#111118",
  surfaceAlt: "#16161f",
  border: "#23232f",
  borderHover: "#33334a",
  orange: "#f97316",
  orangeDim: "#c2590f",
  orangeGlow: "rgba(249,115,22,.12)",
  text: "#e4e4e7",
  textDim: "#8888a0",
  textMuted: "#55556a",
  green: "#22c55e",
  red: "#ef4444",
  blue: "#3b82f6",
  purple: "#a855f7",
  cyan: "#06b6d4",
  mono: "'DM Mono', monospace",
  heading: "'Syne', sans-serif",
  radius: 8,
};

// ─────────────────────────────────────────────
// Splunk → Cribl Conversion Engine
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
    conf: {
      find: parts[1],
      replace: parts[2] || "",
      global: parts[3] === "g",
    },
    description: `SEDCMD: ${name} — s/${parts[1]}/${parts[2]}/${parts[3] || ""}`,
    groupId: "splunk_sed",
    type: "Sed",
  };
}

function convertExtract(name, regex) {
  return {
    id: `extract_${name}`,
    filter: "true",
    conf: {
      regex,
      regexList: [{ regex, fieldName: "" }],
      overwrite: false,
    },
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
      id: `lookup_${name}`,
      filter: "true",
      conf: {
        file: LOOKUP,
        matchMode: "exact",
        reloadPeriodSec: 60,
      },
      description: `LOOKUP: ${name} → ${LOOKUP}`,
      groupId: "splunk_lookup",
      type: "Lookup",
    };
  }

  if (DELIMS) {
    const delimParts = DELIMS.replace(/"/g, "").split(",");
    return {
      id: `delim_extract_${name}`,
      filter: "true",
      conf: {
        type: "delim",
        delimChar: delimParts[0] || ",",
        quoteChar: delimParts[1] || '"',
        fields: FIELDS ? FIELDS.split(",").map((f) => f.trim()) : [],
      },
      description: `Delimited extract: ${name}`,
      groupId: "splunk_delim",
      type: "Parser",
    };
  }

  if (REGEX) {
    const fn = {
      id: `regex_${name}`,
      filter: "true",
      conf: {
        regex: REGEX,
        regexList: [{ regex: REGEX, fieldName: FORMAT || "" }],
        overwrite: false,
      },
      description: `TRANSFORMS: ${name}`,
      groupId: "splunk_transforms",
      type: "Regex Extract",
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
    id: `eval_${name}`,
    filter: "true",
    conf: { add: Object.entries(transform).map(([k, v]) => ({ name: k, value: `'${v}'` })) },
    description: `Eval passthrough: ${name}`,
    groupId: "splunk_eval",
    type: "Eval",
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
        const existing = functions.find((f) => f.id === "auto_timestamp");
        if (!existing) {
          functions.push(
            convertTimestamp(
              directives["TIME_FORMAT"] || directives["time_format"],
              directives["TIME_PREFIX"] || directives["time_prefix"]
            )
          );
          stats.timestamp++;
        }
      } else if (upper === "LINE_BREAKER") {
        functions.push(convertLineBreaker(value));
        stats.linebreak++;
      } else if (key.startsWith("TRANSFORMS-") || key.startsWith("REPORT-")) {
        const refs = value.split(",").map((s) => s.trim());
        for (const ref of refs) {
          if (transforms[ref]) {
            functions.push(convertTransform(ref, transforms[ref]));
            stats.transforms++;
          } else {
            warnings.push(`Transform [${ref}] referenced in [${stanza}] not found in transforms.conf`);
          }
        }
      } else if (upper === "LOOKUP") {
        functions.push({
          id: `lookup_${stanza}`,
          filter: "true",
          conf: { file: value, matchMode: "exact" },
          description: `Lookup: ${value}`,
          groupId: "splunk_lookup",
          type: "Lookup",
        });
        stats.lookup++;
      } else if (!["SHOULD_LINEMERGE", "TRUNCATE", "MAX_TIMESTAMP_LOOKAHEAD", "TZ", "CHARSET"].includes(upper)) {
        stats.other++;
      }
    }
  }

  // Also convert any transforms not referenced by props (standalone)
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
    warnings,
    stats,
    functionCount: functions.length,
  };
}

// ─────────────────────────────────────────────
// Shared Styles
// ─────────────────────────────────────────────

const fontLink = `https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Syne:wght@400;600;700;800&display=swap`;

const globalCSS = `
  @import url('${fontLink}');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: ${T.bg}; color: ${T.text}; font-family: ${T.mono}; }
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: ${T.surface}; }
  ::-webkit-scrollbar-thumb { background: ${T.border}; border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: ${T.borderHover}; }
  ::selection { background: ${T.orange}; color: ${T.bg}; }
`;

const s = {
  app: {
    minHeight: "100vh",
    background: T.bg,
    color: T.text,
    fontFamily: T.mono,
    display: "flex",
    flexDirection: "column",
  },
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "16px 24px",
    borderBottom: `1px solid ${T.border}`,
    background: T.surface,
  },
  logo: {
    fontFamily: T.heading,
    fontSize: 22,
    fontWeight: 800,
    color: T.orange,
    letterSpacing: "-0.02em",
  },
  badge: {
    fontSize: 11,
    background: T.orangeGlow,
    color: T.orange,
    padding: "3px 10px",
    borderRadius: 999,
    border: `1px solid ${T.orange}33`,
    fontFamily: T.mono,
  },
  tabs: {
    display: "flex",
    gap: 0,
    borderBottom: `1px solid ${T.border}`,
    background: T.surface,
    paddingLeft: 24,
    overflowX: "auto",
  },
  tab: (active) => ({
    padding: "12px 20px",
    cursor: "pointer",
    fontSize: 13,
    fontFamily: T.mono,
    fontWeight: active ? 500 : 400,
    color: active ? T.orange : T.textDim,
    background: active ? T.orangeGlow : "transparent",
    borderBottom: active ? `2px solid ${T.orange}` : "2px solid transparent",
    transition: "all .15s ease",
    whiteSpace: "nowrap",
    userSelect: "none",
  }),
  main: {
    flex: 1,
    padding: 24,
    maxWidth: 1280,
    width: "100%",
    margin: "0 auto",
  },
  card: {
    background: T.surface,
    border: `1px solid ${T.border}`,
    borderRadius: T.radius,
    padding: 24,
    marginBottom: 16,
  },
  h2: {
    fontFamily: T.heading,
    fontSize: 18,
    fontWeight: 700,
    color: T.text,
    marginBottom: 12,
  },
  h3: {
    fontFamily: T.heading,
    fontSize: 14,
    fontWeight: 600,
    color: T.textDim,
    textTransform: "uppercase",
    letterSpacing: "0.06em",
    marginBottom: 8,
  },
  textarea: {
    width: "100%",
    minHeight: 260,
    background: T.bg,
    color: T.text,
    border: `1px solid ${T.border}`,
    borderRadius: T.radius,
    padding: 14,
    fontFamily: T.mono,
    fontSize: 13,
    lineHeight: 1.6,
    resize: "vertical",
    outline: "none",
  },
  btn: (variant = "primary") => ({
    padding: "10px 22px",
    fontSize: 13,
    fontFamily: T.mono,
    fontWeight: 500,
    borderRadius: T.radius,
    border: variant === "primary" ? "none" : `1px solid ${T.border}`,
    background: variant === "primary" ? T.orange : "transparent",
    color: variant === "primary" ? "#000" : T.textDim,
    cursor: "pointer",
    transition: "all .15s ease",
    display: "inline-flex",
    alignItems: "center",
    gap: 8,
  }),
  input: {
    width: "100%",
    padding: "10px 14px",
    background: T.bg,
    color: T.text,
    border: `1px solid ${T.border}`,
    borderRadius: T.radius,
    fontFamily: T.mono,
    fontSize: 13,
    outline: "none",
  },
  label: {
    fontSize: 12,
    color: T.textDim,
    marginBottom: 6,
    display: "block",
    fontFamily: T.mono,
  },
  pill: (color) => ({
    display: "inline-block",
    fontSize: 11,
    padding: "2px 10px",
    borderRadius: 999,
    background: `${color}18`,
    color,
    border: `1px solid ${color}33`,
    fontFamily: T.mono,
  }),
  pre: {
    background: T.bg,
    border: `1px solid ${T.border}`,
    borderRadius: T.radius,
    padding: 16,
    fontFamily: T.mono,
    fontSize: 12,
    lineHeight: 1.7,
    color: T.text,
    overflow: "auto",
    maxHeight: 500,
    whiteSpace: "pre-wrap",
    wordBreak: "break-word",
  },
  row: { display: "flex", gap: 16, flexWrap: "wrap" },
  col: { flex: 1, minWidth: 280 },
  stat: {
    textAlign: "center",
    padding: 16,
    background: T.surfaceAlt,
    borderRadius: T.radius,
    border: `1px solid ${T.border}`,
  },
  statNum: {
    fontFamily: T.heading,
    fontSize: 28,
    fontWeight: 800,
    color: T.orange,
  },
  statLabel: {
    fontSize: 11,
    color: T.textDim,
    marginTop: 4,
    fontFamily: T.mono,
  },
  warning: {
    padding: "8px 14px",
    background: `${T.red}12`,
    border: `1px solid ${T.red}33`,
    borderRadius: T.radius,
    color: T.red,
    fontSize: 12,
    marginBottom: 8,
    fontFamily: T.mono,
  },
  fnCard: {
    padding: "12px 16px",
    background: T.surfaceAlt,
    border: `1px solid ${T.border}`,
    borderRadius: T.radius,
    marginBottom: 8,
  },
  fnType: {
    fontSize: 11,
    fontWeight: 600,
    color: T.orange,
    textTransform: "uppercase",
    letterSpacing: "0.05em",
    marginBottom: 4,
  },
  fnDesc: {
    fontSize: 12,
    color: T.textDim,
    lineHeight: 1.5,
  },
  emptyState: {
    textAlign: "center",
    padding: "60px 20px",
    color: T.textMuted,
    fontSize: 14,
  },
  dropZone: (active) => ({
    border: `2px dashed ${active ? T.orange : T.border}`,
    borderRadius: T.radius,
    padding: "48px 24px",
    textAlign: "center",
    cursor: "pointer",
    background: active ? T.orangeGlow : "transparent",
    transition: "all .2s ease",
  }),
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
// Tab Components
// ─────────────────────────────────────────────

function UploadTab({ onLoad }) {
  const [dragActive, setDragActive] = useState(false);
  const [files, setFiles] = useState({ props: null, transforms: null });
  const propsRef = useRef(null);
  const transRef = useRef(null);

  const handleFile = useCallback((file, type) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      setFiles((prev) => ({ ...prev, [type]: { name: file.name, content: e.target.result } }));
    };
    reader.readAsText(file);
  }, []);

  const handleDrop = useCallback(
    (e) => {
      e.preventDefault();
      setDragActive(false);
      for (const file of e.dataTransfer.files) {
        if (file.name.includes("props")) handleFile(file, "props");
        else if (file.name.includes("transforms")) handleFile(file, "transforms");
        else handleFile(file, "props"); // default to props
      }
    },
    [handleFile]
  );

  const handleConvert = () => {
    if (files.props || files.transforms) {
      onLoad(files.props?.content || "", files.transforms?.content || "");
    }
  };

  return (
    <div>
      <div style={s.card}>
        <h2 style={s.h2}>Upload Configuration Files</h2>
        <p style={{ ...s.fnDesc, marginBottom: 20 }}>
          Drop your Splunk Heavy Forwarder <code style={{ color: T.orange }}>props.conf</code> and{" "}
          <code style={{ color: T.orange }}>transforms.conf</code> files here to convert them to Cribl Stream pipelines.
        </p>

        <div
          style={s.dropZone(dragActive)}
          onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
          onDragLeave={() => setDragActive(false)}
          onDrop={handleDrop}
          onClick={() => propsRef.current?.click()}
        >
          <div style={{ fontSize: 36, marginBottom: 12 }}>&#128194;</div>
          <div style={{ color: T.textDim, fontSize: 14, marginBottom: 8 }}>
            Drag &amp; drop .conf files here, or click to browse
          </div>
          <div style={{ color: T.textMuted, fontSize: 12 }}>
            Accepts props.conf and transforms.conf
          </div>
        </div>

        <input
          ref={propsRef}
          type="file"
          accept=".conf,.txt"
          style={{ display: "none" }}
          onChange={(e) => e.target.files[0] && handleFile(e.target.files[0], "props")}
        />
        <input
          ref={transRef}
          type="file"
          accept=".conf,.txt"
          style={{ display: "none" }}
          onChange={(e) => e.target.files[0] && handleFile(e.target.files[0], "transforms")}
        />

        <div style={{ ...s.row, marginTop: 20 }}>
          <div style={s.col}>
            <button style={s.btn("ghost")} onClick={() => propsRef.current?.click()}>
              {files.props ? `✓ ${files.props.name}` : "Select props.conf"}
            </button>
          </div>
          <div style={s.col}>
            <button style={s.btn("ghost")} onClick={() => transRef.current?.click()}>
              {files.transforms ? `✓ ${files.transforms.name}` : "Select transforms.conf"}
            </button>
          </div>
        </div>

        {(files.props || files.transforms) && (
          <div style={{ marginTop: 20 }}>
            <button style={s.btn("primary")} onClick={handleConvert}>
              Convert to Cribl Pipeline →
            </button>
          </div>
        )}
      </div>

      <div style={s.card}>
        <h3 style={s.h3}>Quick Start with Samples</h3>
        <p style={{ ...s.fnDesc, marginBottom: 16 }}>
          Don't have files handy? Load sample configs to explore the converter.
        </p>
        <button style={s.btn("primary")} onClick={() => onLoad(SAMPLE_PROPS, SAMPLE_TRANSFORMS)}>
          Load Sample Data
        </button>
      </div>
    </div>
  );
}

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
    <div style={s.card}>
      <h2 style={s.h2}>Fetch from GitHub</h2>
      <p style={{ ...s.fnDesc, marginBottom: 20 }}>
        Pull <code style={{ color: T.orange }}>props.conf</code> and{" "}
        <code style={{ color: T.orange }}>transforms.conf</code> directly from a GitHub repository.
      </p>

      <div style={{ marginBottom: 16 }}>
        <label style={s.label}>Repository URL</label>
        <input
          style={s.input}
          placeholder="https://github.com/owner/repo"
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
        />
      </div>

      <div style={{ ...s.row, marginBottom: 16 }}>
        <div style={s.col}>
          <label style={s.label}>props.conf path</label>
          <input style={s.input} value={propsPath} onChange={(e) => setPropsPath(e.target.value)} />
        </div>
        <div style={s.col}>
          <label style={s.label}>transforms.conf path</label>
          <input style={s.input} value={transPath} onChange={(e) => setTransPath(e.target.value)} />
        </div>
      </div>

      <div style={{ marginBottom: 16 }}>
        <label style={s.label}>Personal Access Token (optional, for private repos)</label>
        <input
          style={s.input}
          type="password"
          placeholder="ghp_xxxxxxxxxxxx"
          value={token}
          onChange={(e) => setToken(e.target.value)}
        />
      </div>

      {error && <div style={s.warning}>{error}</div>}

      <button style={s.btn("primary")} onClick={handleFetch} disabled={loading || !repoUrl}>
        {loading ? "Fetching…" : "Fetch & Convert →"}
      </button>
    </div>
  );
}

function AnalyzeTab({ result }) {
  if (!result) {
    return <div style={s.emptyState}>Upload or fetch configuration files first to see analysis.</div>;
  }

  const { stats, warnings, functionCount } = result;

  return (
    <div>
      <div style={s.card}>
        <h2 style={s.h2}>Conversion Analysis</h2>

        <div style={{ ...s.row, marginBottom: 24, gap: 12 }}>
          {[
            { label: "Total Functions", value: functionCount, color: T.orange },
            { label: "Sed Commands", value: stats.sed, color: T.cyan },
            { label: "Regex Extracts", value: stats.extract, color: T.green },
            { label: "Transforms", value: stats.transforms, color: T.purple },
            { label: "Timestamp", value: stats.timestamp, color: T.blue },
            { label: "Line Breakers", value: stats.linebreak, color: T.red },
          ].map((item) => (
            <div key={item.label} style={{ ...s.stat, flex: "1 1 130px" }}>
              <div style={{ ...s.statNum, color: item.color }}>{item.value}</div>
              <div style={s.statLabel}>{item.label}</div>
            </div>
          ))}
        </div>
      </div>

      {warnings.length > 0 && (
        <div style={s.card}>
          <h3 style={s.h3}>Warnings</h3>
          {warnings.map((w, i) => (
            <div key={i} style={s.warning}>{w}</div>
          ))}
        </div>
      )}

      <div style={s.card}>
        <h3 style={s.h3}>Pipeline Functions</h3>
        {result.pipeline.conf.functions.map((fn, i) => (
          <div key={i} style={s.fnCard}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
              <span style={s.pill(
                fn.type === "Sed" ? T.cyan :
                fn.type === "Regex Extract" ? T.green :
                fn.type === "Auto Timestamp" ? T.blue :
                fn.type === "Event Breaker" ? T.red :
                fn.type === "Lookup" ? T.purple : T.orange
              )}>
                {fn.type}
              </span>
              <span style={{ fontSize: 13, color: T.text }}>{fn.id}</span>
            </div>
            <div style={s.fnDesc}>{fn.description}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function GenerateTab({ result }) {
  if (!result) {
    return <div style={s.emptyState}>Upload or fetch configuration files first to generate pipeline JSON.</div>;
  }

  const json = JSON.stringify(result.pipeline, null, 2);

  return (
    <div>
      <div style={s.card}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
          <h2 style={{ ...s.h2, marginBottom: 0 }}>Cribl Pipeline JSON</h2>
          <button
            style={s.btn("primary")}
            onClick={() => navigator.clipboard?.writeText(json)}
          >
            Copy to Clipboard
          </button>
        </div>
        <pre style={s.pre}>{json}</pre>
      </div>

      <div style={s.card}>
        <h3 style={s.h3}>Individual Functions</h3>
        {result.pipeline.conf.functions.map((fn, i) => (
          <div key={i} style={{ marginBottom: 16 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
              <span style={s.pill(T.orange)}>{fn.type}: {fn.id}</span>
              <button
                style={{ ...s.btn("ghost"), fontSize: 11, padding: "4px 12px" }}
                onClick={() => navigator.clipboard?.writeText(JSON.stringify(fn, null, 2))}
              >
                Copy
              </button>
            </div>
            <pre style={{ ...s.pre, maxHeight: 200 }}>{JSON.stringify(fn, null, 2)}</pre>
          </div>
        ))}
      </div>
    </div>
  );
}

function ExportTab({ result }) {
  if (!result) {
    return <div style={s.emptyState}>Upload or fetch configuration files first to export.</div>;
  }

  const pipelineJson = JSON.stringify(result.pipeline, null, 2);

  const downloadFile = (content, filename, mime = "application/json") => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const criblBundle = {
    pipelines: {
      [result.pipeline.id]: {
        conf: result.pipeline.conf,
        description: result.pipeline.description,
      },
    },
  };

  return (
    <div>
      <div style={s.card}>
        <h2 style={s.h2}>Export Options</h2>
        <div style={{ ...s.row, gap: 12 }}>
          {[
            {
              label: "Pipeline JSON",
              desc: "Standard Cribl pipeline configuration",
              action: () => downloadFile(pipelineJson, "pipeline.json"),
            },
            {
              label: "Cribl Bundle",
              desc: "Import-ready bundle for Cribl Stream",
              action: () => downloadFile(JSON.stringify(criblBundle, null, 2), "cribl-bundle.json"),
            },
            {
              label: "Functions Only",
              desc: "Array of pipeline functions",
              action: () =>
                downloadFile(
                  JSON.stringify(result.pipeline.conf.functions, null, 2),
                  "functions.json"
                ),
            },
            {
              label: "Analysis Report",
              desc: "Conversion summary with warnings",
              action: () =>
                downloadFile(
                  JSON.stringify(
                    { stats: result.stats, warnings: result.warnings, functionCount: result.functionCount },
                    null,
                    2
                  ),
                  "analysis.json"
                ),
            },
          ].map((item) => (
            <div
              key={item.label}
              style={{
                ...s.fnCard,
                flex: "1 1 200px",
                cursor: "pointer",
                transition: "border-color .15s",
              }}
              onClick={item.action}
              onMouseEnter={(e) => (e.currentTarget.style.borderColor = T.orange)}
              onMouseLeave={(e) => (e.currentTarget.style.borderColor = T.border)}
            >
              <div style={{ ...s.fnType, marginBottom: 8 }}>{item.label}</div>
              <div style={s.fnDesc}>{item.desc}</div>
              <div style={{ marginTop: 12 }}>
                <button style={s.btn("primary")}>Download</button>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div style={s.card}>
        <h3 style={s.h3}>Clipboard</h3>
        <p style={{ ...s.fnDesc, marginBottom: 12 }}>Copy the full pipeline JSON for pasting into Cribl Stream.</p>
        <button style={s.btn("primary")} onClick={() => navigator.clipboard?.writeText(pipelineJson)}>
          Copy Pipeline JSON
        </button>
      </div>
    </div>
  );
}

function StanzaLabTab() {
  const [propsText, setPropsText] = useState(SAMPLE_PROPS);
  const [transText, setTransText] = useState(SAMPLE_TRANSFORMS);

  const result = useMemo(() => {
    try {
      return buildPipeline(propsText, transText);
    } catch {
      return null;
    }
  }, [propsText, transText]);

  const json = result ? JSON.stringify(result.pipeline.conf.functions, null, 2) : "// Enter valid conf to see output";

  return (
    <div>
      <div style={s.card}>
        <h2 style={s.h2}>Stanza Lab</h2>
        <p style={{ ...s.fnDesc, marginBottom: 20 }}>
          Edit props.conf and transforms.conf stanzas in real-time. The Cribl pipeline functions update live as you type.
        </p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <div>
          <div style={s.card}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
              <h3 style={{ ...s.h3, marginBottom: 0 }}>props.conf</h3>
              <span style={s.pill(T.cyan)}>{Object.keys(parseINI(propsText)).length} stanzas</span>
            </div>
            <textarea
              style={{ ...s.textarea, minHeight: 360 }}
              value={propsText}
              onChange={(e) => setPropsText(e.target.value)}
              spellCheck={false}
              placeholder="[source::syslog]&#10;TIME_FORMAT = %b %d %H:%M:%S"
            />
          </div>

          <div style={s.card}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
              <h3 style={{ ...s.h3, marginBottom: 0 }}>transforms.conf</h3>
              <span style={s.pill(T.purple)}>{Object.keys(parseINI(transText)).length} stanzas</span>
            </div>
            <textarea
              style={{ ...s.textarea, minHeight: 360 }}
              value={transText}
              onChange={(e) => setTransText(e.target.value)}
              spellCheck={false}
              placeholder="[my_transform]&#10;REGEX = (\w+)=(\S+)"
            />
          </div>
        </div>

        <div>
          <div style={s.card}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
              <h3 style={{ ...s.h3, marginBottom: 0 }}>Cribl Pipeline Functions</h3>
              {result && <span style={s.pill(T.green)}>{result.functionCount} functions</span>}
            </div>
            <pre style={{ ...s.pre, minHeight: 300, maxHeight: 500 }}>{json}</pre>
            <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
              <button style={s.btn("primary")} onClick={() => navigator.clipboard?.writeText(json)}>
                Copy JSON
              </button>
              <button
                style={s.btn("ghost")}
                onClick={() =>
                  navigator.clipboard?.writeText(
                    result ? JSON.stringify(result.pipeline, null, 2) : ""
                  )
                }
              >
                Copy Full Pipeline
              </button>
            </div>
          </div>

          {result && result.warnings.length > 0 && (
            <div style={s.card}>
              <h3 style={s.h3}>Warnings</h3>
              {result.warnings.map((w, i) => (
                <div key={i} style={s.warning}>{w}</div>
              ))}
            </div>
          )}

          {result && (
            <div style={s.card}>
              <h3 style={s.h3}>Function Breakdown</h3>
              <div style={{ ...s.row, gap: 8 }}>
                {result.pipeline.conf.functions.map((fn, i) => (
                  <div key={i} style={{ ...s.fnCard, flex: "1 1 100%" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                      <span style={s.pill(
                        fn.type === "Sed" ? T.cyan :
                        fn.type === "Regex Extract" ? T.green :
                        fn.type === "Auto Timestamp" ? T.blue :
                        fn.type === "Event Breaker" ? T.red :
                        fn.type === "Lookup" ? T.purple : T.orange
                      )}>
                        {fn.type}
                      </span>
                      <span style={{ fontSize: 12, color: T.text }}>{fn.id}</span>
                    </div>
                    <div style={s.fnDesc}>{fn.description}</div>
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

const TABS = ["Upload", "GitHub", "Analyze", "Generate", "Export", "Stanza Lab"];

export default function HFCriblConverter() {
  const [activeTab, setActiveTab] = useState("Upload");
  const [propsText, setPropsText] = useState("");
  const [transText, setTransText] = useState("");
  const [result, setResult] = useState(null);

  const handleLoad = useCallback((props, transforms) => {
    setPropsText(props);
    setTransText(transforms);
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
      case "Upload":
        return <UploadTab onLoad={handleLoad} />;
      case "GitHub":
        return <GitHubTab onLoad={handleLoad} />;
      case "Analyze":
        return <AnalyzeTab result={result} />;
      case "Generate":
        return <GenerateTab result={result} />;
      case "Export":
        return <ExportTab result={result} />;
      case "Stanza Lab":
        return <StanzaLabTab />;
      default:
        return null;
    }
  };

  return (
    <div style={s.app}>
      <header style={s.header}>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <span style={s.logo}>DATADAY</span>
          <span style={{ color: T.textMuted, fontSize: 13 }}>|</span>
          <span style={{ color: T.textDim, fontSize: 14, fontFamily: T.heading }}>
            HF → Cribl Converter
          </span>
        </div>
        <span style={s.badge}>v1.0.0</span>
      </header>

      <nav style={s.tabs}>
        {TABS.map((tab) => (
          <div key={tab} style={s.tab(activeTab === tab)} onClick={() => setActiveTab(tab)}>
            {tab}
          </div>
        ))}
      </nav>

      <main style={s.main}>{renderTab()}</main>

      <footer
        style={{
          padding: "16px 24px",
          borderTop: `1px solid ${T.border}`,
          background: T.surface,
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          fontSize: 11,
          color: T.textMuted,
        }}
      >
        <span>DataDay Technology Solutions</span>
        <span>Splunk HF → Cribl Stream Pipeline Converter</span>
      </footer>
    </div>
  );
}
