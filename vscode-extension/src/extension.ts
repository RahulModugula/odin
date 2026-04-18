import * as vscode from "vscode";
import { OdinDiagnosticsProvider } from "./diagnostics";
import { runOdinReview } from "./reviewProvider";

const SUPPORTED_LANGUAGES = new Set([
  "python",
  "javascript",
  "javascriptreact",
  "typescript",
  "typescriptreact",
  "go",
  "rust",
  "java",
]);

let diagnostics: OdinDiagnosticsProvider;

export function activate(ctx: vscode.ExtensionContext): void {
  diagnostics = new OdinDiagnosticsProvider();
  ctx.subscriptions.push(diagnostics);

  // ── On-save: run instant rules-only review ─────────────────────────────
  ctx.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      if (!shouldReview(doc)) return;
      const cfg = vscode.workspace.getConfiguration("odin");
      if (!cfg.get<boolean>("enable", true)) return;
      if (!cfg.get<boolean>("reviewOnSave", true)) return;
      await reviewDocument(doc, { fullReview: false, quiet: true });
    })
  );

  // ── On demand: quick rules review (Cmd+Shift+P → "Odin: Review Current File") ─
  ctx.subscriptions.push(
    vscode.commands.registerCommand("odin.reviewFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage("Odin: no active editor.");
        return;
      }
      await reviewDocument(editor.document, { fullReview: false, quiet: false });
    })
  );

  // ── On demand: full AI + taint review ──────────────────────────────────
  ctx.subscriptions.push(
    vscode.commands.registerCommand("odin.fullReview", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage("Odin: no active editor.");
        return;
      }
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "Odin: full review (rules + AI + taint)…",
          cancellable: false,
        },
        async () => {
          await reviewDocument(editor.document, {
            fullReview: true,
            quiet: false,
          });
        }
      );
    })
  );

  // ── On demand: clear all diagnostics ───────────────────────────────────
  ctx.subscriptions.push(
    vscode.commands.registerCommand("odin.clearDiagnostics", () => {
      diagnostics.clearAll();
    })
  );

  // Clean up diagnostics for closed documents
  ctx.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => {
      diagnostics.clear(doc.uri);
    })
  );
}

export function deactivate(): void {
  diagnostics?.dispose();
}

function shouldReview(doc: vscode.TextDocument): boolean {
  return SUPPORTED_LANGUAGES.has(doc.languageId) && doc.uri.scheme === "file";
}

interface ReviewOptions {
  fullReview: boolean;
  quiet: boolean;
}

async function reviewDocument(
  doc: vscode.TextDocument,
  options: ReviewOptions
): Promise<void> {
  try {
    const findings = await runOdinReview(doc, {
      fullReview: options.fullReview,
    });
    diagnostics.update(doc.uri, findings);
    if (!options.quiet) {
      const summary =
        findings.length === 0
          ? "Odin: no findings."
          : `Odin: ${findings.length} finding${findings.length === 1 ? "" : "s"}.`;
      vscode.window.setStatusBarMessage(summary, 4000);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (!options.quiet) {
      vscode.window.showErrorMessage(`Odin review failed: ${message}`);
    } else {
      // On auto-save failures, log to the output channel instead of popping a modal.
      console.warn("Odin on-save review failed:", message);
    }
  }
}
