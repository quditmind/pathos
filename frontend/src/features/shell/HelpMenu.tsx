import * as DM from "@radix-ui/react-dropdown-menu";
import { Link } from "@tanstack/react-router";
import { Activity, BookOpen, Bug, Code2, HelpCircle, Info, Keyboard, LifeBuoy, PanelRight, Sparkles } from "lucide-react";
import type { ReactNode } from "react";
import { bundleVersion, displayVersion, useMeta } from "./meta";
import { useShell } from "./ShellProvider";

const itemCls =
  "flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-[13px] outline-none data-highlighted:bg-surface-muted [&_svg]:size-4 [&_svg]:text-muted-foreground";

function Item({ icon, children, onSelect, hint }: { icon: ReactNode; children: ReactNode; onSelect: () => void; hint?: string }) {
  return (
    <DM.Item className={itemCls} onSelect={onSelect}>
      {icon}
      <span className="flex-1">{children}</span>
      {hint && <kbd className="rounded border border-border px-1 text-[10px] text-muted-foreground">{hint}</kbd>}
    </DM.Item>
  );
}

function LinkItem({ icon, to, children }: { icon: ReactNode; to: string; children: ReactNode }) {
  return (
    <DM.Item asChild className={itemCls}>
      <Link to={to as never}>
        {icon}
        <span className="flex-1">{children}</span>
      </Link>
    </DM.Item>
  );
}

/** The (?) Help menu in the top bar (prompt §2.3). Everything works offline. */
export function HelpMenu() {
  const { open, reportProblem } = useShell();
  const meta = useMeta();
  const v = meta.data?.version || bundleVersion;
  return (
    <DM.Root>
      <DM.Trigger
        className="flex items-center gap-1.5 rounded-md px-2 py-1.5 text-[13px] text-muted-foreground hover:bg-surface-muted hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring"
        aria-label="Help"
      >
        <HelpCircle className="size-4" />
        <span className="hidden sm:inline">Help</span>
      </DM.Trigger>
      <DM.Portal>
        <DM.Content align="end" sideOffset={6} className="z-50 min-w-64 rounded-md border border-border bg-surface p-1 shadow-lg" aria-label="Help menu">
          <Item icon={<PanelRight />} onSelect={() => open("help")} hint="F1">
            Help for this page
          </Item>
          <LinkItem icon={<BookOpen />} to="/help">
            Help centre
          </LinkItem>
          <LinkItem icon={<LifeBuoy />} to="/help/troubleshooting">
            Troubleshooting centre
          </LinkItem>
          <Item icon={<Keyboard />} onSelect={() => open("shortcuts")}>
            Keyboard shortcuts
          </Item>
          <Item icon={<Sparkles />} onSelect={() => open("whatsnew")}>
            What&apos;s new in {displayVersion(v) || "PATHOS"}
          </Item>
          <LinkItem icon={<Code2 />} to="/help/api-reference/index">
            API reference
          </LinkItem>
          <DM.Separator className="my-1 h-px bg-border" />
          <Item icon={<Activity />} onSelect={() => open("status")}>
            System status
          </Item>
          <Item icon={<Bug />} onSelect={reportProblem}>
            Report a problem
          </Item>
          <Item icon={<Info />} onSelect={() => open("about")}>
            About PATHOS
          </Item>
        </DM.Content>
      </DM.Portal>
    </DM.Root>
  );
}
