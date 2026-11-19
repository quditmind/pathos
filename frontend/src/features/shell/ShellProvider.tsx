import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useRouterState } from "@tanstack/react-router";
import { toast } from "@/components/ui/toast";
import { AboutDialog } from "./AboutDialog";
import { buildDiagnosticBundle, downloadDiagnosticBundle } from "./diagnostics";
import { HelpDrawer } from "./HelpDrawer";
import { useMeta } from "./meta";
import { ShortcutsDialog } from "./ShortcutsDialog";
import { SystemStatusDialog } from "./SystemStatusDialog";
import { WhatsNewDialog } from "./WhatsNewDialog";

export type ShellPanel = "help" | "about" | "shortcuts" | "whatsnew" | "status";

interface ShellValue {
  panel: ShellPanel | null;
  open: (p: ShellPanel) => void;
  close: () => void;
  reportProblem: () => void;
}

const ShellContext = createContext<ShellValue | null>(null);

export function useShell(): ShellValue {
  const v = useContext(ShellContext);
  if (!v) throw new Error("useShell outside ShellProvider");
  return v;
}

/** True when the key event comes from a text field (shortcuts must not fire). */
export function isTyping(e: KeyboardEvent): boolean {
  const t = e.target as HTMLElement | null;
  if (!t || !(t instanceof HTMLElement)) return false;
  return t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName) || t.closest("[role=combobox],[cmdk-root]") !== null;
}

/** F1 or ? opens help for the current page. */
export function useHelpHotkey(onHelp: () => void) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "F1") {
        e.preventDefault();
        onHelp();
        return;
      }
      if (e.key === "?" && !e.ctrlKey && !e.metaKey && !e.altKey && !isTyping(e)) {
        e.preventDefault();
        onHelp();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onHelp]);
}

/** Holds the Help menu's dialogs and drawer, and the F1 / ? shortcut. */
export function ShellProvider({ children }: { children: ReactNode }) {
  const [panel, setPanel] = useState<ShellPanel | null>(null);
  const meta = useMeta();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const open = useCallback((p: ShellPanel) => setPanel(p), []);
  const close = useCallback(() => setPanel(null), []);
  const openHelp = useCallback(() => setPanel("help"), []);
  useHelpHotkey(openHelp);
  const reportProblem = useCallback(() => {
    downloadDiagnosticBundle(buildDiagnosticBundle({ meta: meta.data, pathname }));
    toast.success("Diagnostic bundle downloaded. It holds no tokens, secrets, source code or finding contents.");
  }, [meta.data, pathname]);
  const value = useMemo(() => ({ panel, open, close, reportProblem }), [panel, open, close, reportProblem]);
  const onOpenChange = (o: boolean) => !o && close();
  return (
    <ShellContext.Provider value={value}>
      {children}
      <HelpDrawer open={panel === "help"} onOpenChange={onOpenChange} />
      <AboutDialog open={panel === "about"} onOpenChange={onOpenChange} />
      <ShortcutsDialog open={panel === "shortcuts"} onOpenChange={onOpenChange} />
      <WhatsNewDialog open={panel === "whatsnew"} onOpenChange={onOpenChange} />
      <SystemStatusDialog open={panel === "status"} onOpenChange={onOpenChange} />
    </ShellContext.Provider>
  );
}
