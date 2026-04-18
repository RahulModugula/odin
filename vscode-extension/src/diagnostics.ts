import * as vscode from "vscode";
import type { OdinFinding } from "./reviewProvider";

/** Bridges Odin's finding JSON to VS Code's Diagnostic API. */
export class OdinDiagnosticsProvider implements vscode.Disposable {
  private readonly collection: vscode.DiagnosticCollection;

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection("odin");
  }

  update(uri: vscode.Uri, findings: OdinFinding[]): void {
    const minSeverity = vscode.workspace
      .getConfiguration("odin")
      .get<string>("minSeverity", "low");
    const threshold = severityOrder(minSeverity);

    const diagnostics = findings
      .filter((f) => severityOrder(f.severity) <= threshold)
      .map((f) => toDiagnostic(f));
    this.collection.set(uri, diagnostics);
  }

  clear(uri: vscode.Uri): void {
    this.collection.delete(uri);
  }

  clearAll(): void {
    this.collection.clear();
  }

  dispose(): void {
    this.collection.dispose();
  }
}

function toDiagnostic(finding: OdinFinding): vscode.Diagnostic {
  const startLine = Math.max(0, (finding.line_start ?? 1) - 1);
  const endLine = Math.max(
    startLine,
    (finding.line_end ?? finding.line_start ?? 1) - 1
  );
  const range = new vscode.Range(startLine, 0, endLine, Number.MAX_SAFE_INTEGER);

  const confidencePct =
    typeof finding.confidence === "number"
      ? ` (${Math.round(finding.confidence * 100)}%)`
      : "";
  const source = finding.source ? `[${finding.source}]` : "";
  const message = [
    `${finding.title}${confidencePct}`,
    finding.description,
    finding.suggestion ? `→ ${finding.suggestion}` : null,
    finding.attack_scenario ? `Attack: ${finding.attack_scenario}` : null,
  ]
    .filter(Boolean)
    .join("\n\n");

  const diag = new vscode.Diagnostic(
    range,
    message,
    toVSCodeSeverity(finding.severity)
  );
  diag.source = ["Odin", source].filter(Boolean).join(" ");
  diag.code = finding.rule_id ?? finding.title;
  return diag;
}

function toVSCodeSeverity(severity: string): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

/** Lower number = more severe — so <= threshold means "at this level or worse". */
function severityOrder(sev: string): number {
  switch (sev) {
    case "critical":
      return 0;
    case "high":
      return 1;
    case "medium":
      return 2;
    case "low":
      return 3;
    default:
      return 4;
  }
}
