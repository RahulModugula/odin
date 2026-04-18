import { spawn } from "node:child_process";
import * as path from "node:path";
import * as vscode from "vscode";

export interface OdinFinding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  category?: string;
  title: string;
  description: string;
  line_start?: number;
  line_end?: number;
  suggestion?: string;
  fix_code?: string;
  attack_scenario?: string;
  confidence?: number;
  source?: string;
  rule_id?: string;
  file?: string;
}

interface ReviewOptions {
  fullReview: boolean;
}

/** Runs `odin review <file> --json` and returns the parsed findings. */
export async function runOdinReview(
  doc: vscode.TextDocument,
  options: ReviewOptions
): Promise<OdinFinding[]> {
  const cfg = vscode.workspace.getConfiguration("odin");
  const cliPath = cfg.get<string>("cliPath", "uvx");
  const extraArgs = cfg.get<string[]>("extraArgs", []);
  const apiUrl = cfg.get<string>("apiUrl", "");

  const args: string[] = [];
  if (cliPath === "uvx") {
    args.push("odin-review");
  }

  args.push("review", doc.fileName, "--json", "--quiet");

  if (!options.fullReview) {
    args.push("--rules-only");
  } else if (!apiUrl) {
    // No server URL supplied → run the full pipeline in-process
    args.push("--local");
  }

  args.push(...extraArgs);

  const cwd = workspaceFolderFor(doc);
  const env = { ...process.env };
  if (apiUrl) env.ODIN_API_URL = apiUrl;

  const { stdout, stderr, code } = await execute(cliPath, args, { cwd, env });
  if (code !== 0 && code !== 1) {
    // `odin review --fail-on` exits 1 when findings are present — that's not a failure
    throw new Error(
      stderr.trim() || `Odin exited with code ${code}. stdout: ${stdout.slice(0, 500)}`
    );
  }

  return parseFindings(stdout);
}

function workspaceFolderFor(doc: vscode.TextDocument): string | undefined {
  const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
  if (folder) return folder.uri.fsPath;
  return path.dirname(doc.uri.fsPath);
}

interface ExecResult {
  stdout: string;
  stderr: string;
  code: number;
}

function execute(
  command: string,
  args: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv }
): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      shell: false,
    });

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk.toString()));
    child.stderr.on("data", (chunk) => (stderr += chunk.toString()));

    child.on("error", (err) => reject(err));
    child.on("close", (code) =>
      resolve({ stdout, stderr, code: code ?? -1 })
    );
  });
}

/**
 * `odin review --json` prints a banner followed by a JSON array. Parse the last
 * JSON document in stdout, which is robust to the human-readable preamble.
 */
function parseFindings(stdout: string): OdinFinding[] {
  const trimmed = stdout.trim();
  if (!trimmed) return [];

  // Fast path: whole stdout is already JSON
  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) return parsed as OdinFinding[];
  } catch {
    // fall through to bracket scan
  }

  const startIdx = trimmed.indexOf("\n[");
  if (startIdx >= 0) {
    const candidate = trimmed.slice(startIdx + 1);
    try {
      const parsed = JSON.parse(candidate);
      if (Array.isArray(parsed)) return parsed as OdinFinding[];
    } catch {
      // no-op
    }
  }

  return [];
}
