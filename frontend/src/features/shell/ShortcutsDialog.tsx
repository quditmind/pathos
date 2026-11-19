import { Dialog } from "@/components/ui/dialog";

const mod = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform) ? "⌘" : "Ctrl";

/** Every keyboard shortcut in PATHOS. */
export const shortcuts: { keys: string[]; action: string; where: string }[] = [
  { keys: [mod, "K"], action: "Open search and the command palette", where: "Everywhere" },
  { keys: ["F1"], action: "Help for this page", where: "Everywhere" },
  { keys: ["?"], action: "Help for this page (not while typing)", where: "Everywhere" },
  { keys: ["Esc"], action: "Close a dialog, drawer or menu", where: "Everywhere" },
  { keys: ["Tab"], action: "Move to the next control; Shift+Tab moves back", where: "Everywhere" },
  { keys: ["↑", "↓"], action: "Move through menu, palette and list options", where: "Menus and the command palette" },
  { keys: ["Enter"], action: "Open the selected row or result", where: "Tables, review queue, context graph, command palette" },
  { keys: ["Space"], action: "Open the selected graph node", where: "Context graph" },
  { keys: ["Enter"], action: "Send the question", where: "AI Security Analyst" },
  { keys: ["Shift", "Enter"], action: "New line in the question", where: "AI Security Analyst" },
];

export function ShortcutsDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title="Keyboard shortcuts" description="Shortcuts that work in PATHOS.">
      <table className="w-full text-[13px]">
        <thead className="sr-only">
          <tr>
            <th>Keys</th>
            <th>Action</th>
            <th>Where</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {shortcuts.map((s, i) => (
            <tr key={i}>
              <td className="py-2 pr-3 whitespace-nowrap">
                {s.keys.map((k, j) => (
                  <span key={j}>
                    {j > 0 && <span className="px-0.5 text-muted-foreground">+</span>}
                    <kbd className="rounded border border-border bg-surface-muted px-1.5 py-0.5 font-sans text-[11px] font-medium">{k}</kbd>
                  </span>
                ))}
              </td>
              <td className="py-2 pr-3">{s.action}</td>
              <td className="py-2 text-[12px] text-muted-foreground">{s.where}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Dialog>
  );
}
