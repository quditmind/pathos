import { useEffect, useState } from "react";
import { generatedByStamp } from "@/lib/buildStamp";
import { useMeta } from "./meta";

/**
 * Print-only footer on every page (window.print on Executive overview,
 * Reports, Review reports and others): which PATHOS release and build
 * produced the printout, and when. Hidden on screen.
 */
export function PrintStamp() {
  const meta = useMeta();
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const update = () => setNow(new Date());
    window.addEventListener("beforeprint", update);
    return () => window.removeEventListener("beforeprint", update);
  }, []);
  return (
    <div className="hidden border-t border-border px-6 pt-2 text-[11px] text-muted-foreground print:block" data-testid="print-stamp">
      {generatedByStamp({ version: meta.data?.version, commit: meta.data?.commit }, now)}
    </div>
  );
}
