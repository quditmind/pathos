import { useMemo } from "react";
import { Dialog } from "@/components/ui/dialog";
import { renderDoc } from "@/features/help/content";
import { changelogFor } from "./bundled";
import { bundleVersion, displayVersion, useMeta } from "./meta";

/** Renders the current version's CHANGELOG.md section (bundled at build time). */
export function WhatsNewDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const meta = useMeta();
  const version = meta.data?.version || bundleVersion;
  const section = useMemo(() => changelogFor(version), [version]);
  const html = useMemo(() => (section ? renderDoc({ section: "user-guide", body: section.body, headings: [] }) : ""), [section]);
  const label = section?.version.toLowerCase() === "unreleased" ? "Unreleased changes" : section ? displayVersion(section.version) : displayVersion(version);
  return (
    <Dialog open={open} onOpenChange={onOpenChange} size="xl" title={`What's new in ${displayVersion(version) || "PATHOS"}`} description={section ? `${label}${section.date ? ` · ${section.date}` : ""}` : undefined}>
      {section ? (
        <article className="help-prose" dangerouslySetInnerHTML={{ __html: html }} />
      ) : (
        <p className="text-[13px] text-muted-foreground">The release notes are not bundled with this build.</p>
      )}
    </Dialog>
  );
}
