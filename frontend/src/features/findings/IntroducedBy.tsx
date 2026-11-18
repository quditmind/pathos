import type { Finding } from "@/api/types";
import { formatDateTime } from "@/lib/utils";

/**
 * The commit that introduced a code finding (git blame of the scanned
 * commit). Shown for code, secret and IaC findings with a file and line.
 */
export function IntroducedBy({ f }: { f: Pick<Finding, "introduced_status" | "introduced_commit_sha" | "introduced_author" | "introduced_at"> }) {
  const st = f.introduced_status;
  if (!st) return null;
  return (
    <div className="col-span-2" data-testid="introduced-by">
      <dt className="text-[12px] text-muted-foreground">Introduced by</dt>
      <dd className="text-[12.5px]">
        {st === "known" && f.introduced_commit_sha ? (
          <span title="git blame of the scanned commit: the commit that last changed this line">
            commit <span className="font-mono text-[12px]">{f.introduced_commit_sha.slice(0, 12)}</span>
            {f.introduced_author && <> by {f.introduced_author}</>}
            {f.introduced_at && <span className="tabular text-muted-foreground"> · {formatDateTime(f.introduced_at)}</span>}
          </span>
        ) : st === "shallow_clone" ? (
          <span className="text-muted-foreground" title="Enable full history on the repository to record introducing commits">
            Unknown (shallow clone)
          </span>
        ) : (
          <span className="text-muted-foreground">Unknown (the line is not in the scanned commit)</span>
        )}
      </dd>
    </div>
  );
}
