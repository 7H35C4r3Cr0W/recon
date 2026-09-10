import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";

interface Finding {
  value?: string; kind?: string; port?: number | string;
  _host?: string; _category?: string;
}

// severity category -> theme colour (finding_severity: vulnerable is strongest)
const CAT_COLOR: Record<string, string> = {
  vulnerable: "var(--red)", "relay-risk": "var(--gold)", exposure: "var(--blue)",
  access: "var(--blue)", reference: "var(--grey)", info: "var(--grey)",
};

function inline(text: string, key: string) {
  // minimal inline markdown: **bold** and `code`
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).filter(Boolean);
  return parts.map((p, i) => {
    if (p.startsWith("**") && p.endsWith("**")) return <strong key={`${key}-${i}`}>{p.slice(2, -2)}</strong>;
    if (p.startsWith("`") && p.endsWith("`")) return <code key={`${key}-${i}`}>{p.slice(1, -1)}</code>;
    return <span key={`${key}-${i}`}>{p}</span>;
  });
}

// Small, safe markdown renderer for the report shape (headings, tables, lists, hr, paragraphs).
function Markdown({ md }: { md: string }) {
  const lines = md.split("\n");
  const out: React.ReactNode[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (/^#{1,6}\s/.test(line)) {
      const level = line.match(/^#+/)![0].length;
      const txt = line.replace(/^#+\s/, "");
      const Tag = (`h${Math.min(level + 1, 6)}`) as keyof JSX.IntrinsicElements;
      out.push(<Tag key={i} style={{ marginTop: 18, marginBottom: 6 }}>{inline(txt, `h${i}`)}</Tag>);
      i++;
    } else if (/^\s*\|.*\|\s*$/.test(line)) {
      const rows: string[] = [];
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) { rows.push(lines[i]); i++; }
      const cells = (r: string) => r.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
      const header = cells(rows[0]);
      const body = rows.slice(1).filter((r) => !/^\s*\|?[\s:|-]+\|?\s*$/.test(r)).map(cells);
      out.push(
        <div key={i} style={{ overflowX: "auto" }}>
          <table className="rpt-table">
            <thead><tr>{header.map((h, j) => <th key={j}>{inline(h, `th${i}-${j}`)}</th>)}</tr></thead>
            <tbody>{body.map((r, ri) => <tr key={ri}>{r.map((c, ci) => <td key={ci}>{inline(c, `td${i}-${ri}-${ci}`)}</td>)}</tr>)}</tbody>
          </table>
        </div>,
      );
    } else if (/^\s*[-*]\s/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*[-*]\s/.test(lines[i])) { items.push(lines[i].replace(/^\s*[-*]\s/, "")); i++; }
      out.push(<ul key={i}>{items.map((it, j) => <li key={j}>{inline(it, `li${i}-${j}`)}</li>)}</ul>);
    } else if (/^\s*---+\s*$/.test(line)) {
      out.push(<hr key={i} style={{ borderColor: "var(--line)", margin: "16px 0" }} />); i++;
    } else if (line.trim() === "") {
      i++;
    } else {
      out.push(<p key={i} style={{ margin: "6px 0" }}>{inline(line, `p${i}`)}</p>); i++;
    }
  }
  return <>{out}</>;
}

export function Report() {
  const { projectId } = useParams();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [markdown, setMarkdown] = useState<string>("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    Promise.all([
      api<{ findings: Finding[] }>(`/projects/${projectId}/findings`).catch(() => ({ findings: [] })),
      api<{ markdown: string }>(`/projects/${projectId}/report`).catch(() => ({ markdown: "" })),
    ]).then(([f, r]) => {
      if (!alive) return;
      setFindings(f.findings || []);
      setMarkdown(r.markdown || "");
      setLoading(false);
    }).catch((e) => { if (alive) { setErr(String(e)); setLoading(false); } });
    return () => { alive = false; };
  }, [projectId]);

  async function downloadExport() {
    try {
      const bundle = await api(`/projects/${projectId}/export`, { method: "POST" });
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `nabu-export-${projectId}.json`; a.click();
      URL.revokeObjectURL(url);
    } catch (e) { setErr(String(e)); }
  }

  return (
    <div style={{ maxWidth: 900 }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h1>Report &amp; outputs</h1>
        <span className="row" style={{ gap: 8 }}>
          <button className="btn" onClick={downloadExport}>⬇ Export</button>
          <Link className="btn" to={`/projects/${projectId}`}>← project</Link>
        </span>
      </div>
      {err && <p className="err">{err}</p>}
      {loading && <p className="muted">Loading…</p>}

      {!loading && (
        <div className="card" style={{ marginBottom: 14 }}>
          <h3>Findings ({findings.length})</h3>
          {findings.length === 0 ? (
            <p className="muted" style={{ fontSize: 13 }}>No findings yet — run recon to populate this.</p>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table className="rpt-table">
                <thead><tr><th>Severity</th><th>Host</th><th>Port</th><th>Finding</th></tr></thead>
                <tbody>
                  {findings.map((f, i) => (
                    <tr key={i}>
                      <td><span className="pill" style={{ color: CAT_COLOR[f._category || "info"], borderColor: CAT_COLOR[f._category || "info"] }}>{f._category || "info"}</span></td>
                      <td className="mono">{f._host || "—"}</td>
                      <td className="mono">{f.port ?? "—"}</td>
                      <td>{String(f.value ?? f.kind ?? "")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {!loading && (
        <div className="card">
          <h3>Full report</h3>
          {markdown.trim() ? <Markdown md={markdown} /> :
            <p className="muted" style={{ fontSize: 13 }}>No report yet — the first run will generate one.</p>}
        </div>
      )}
    </div>
  );
}
