// Lightweight, dependency-free syntax highlighting for the review code
// viewer. It tokenizes one line at a time (block comments and multi-line
// strings carry state between lines) and never produces HTML: callers render
// tokens as React text, so source code cannot inject markup.

export type TokenKind = "kw" | "str" | "com" | "num" | "fn" | "type" | "plain";
export interface Token {
  kind: TokenKind;
  text: string;
}

interface LangDef {
  keywords: Set<string>;
  line?: string[]; // line comment prefixes
  block?: [string, string]; // block comment delimiters
  quotes: string[];
  multiQuotes?: string[]; // triple-quoted strings (Python)
}

const kw = (s: string) => new Set(s.split(/\s+/).filter(Boolean));

const C_LIKE = "if else for while do switch case break continue return default goto try catch finally throw throws new delete this super class interface extends implements import export from package public private protected static final const let var void null true false undefined typeof instanceof in of async await yield function func struct enum type map chan go defer select range fallthrough nil abstract override virtual using namespace sizeof operator template typename";

const langs: Record<string, LangDef> = {
  go: { keywords: kw(C_LIKE + " string int int64 uint error bool byte rune float64 any"), line: ["//"], block: ["/*", "*/"], quotes: ['"', "'", "`"] },
  javascript: { keywords: kw(C_LIKE + " require module"), line: ["//"], block: ["/*", "*/"], quotes: ['"', "'", "`"] },
  typescript: { keywords: kw(C_LIKE + " readonly declare keyof as is string number boolean unknown never any"), line: ["//"], block: ["/*", "*/"], quotes: ['"', "'", "`"] },
  java: { keywords: kw(C_LIKE + " boolean int long double float char byte short synchronized volatile transient native assert"), line: ["//"], block: ["/*", "*/"], quotes: ['"', "'"] },
  kotlin: { keywords: kw(C_LIKE + " fun val when object data sealed open lateinit companion is"), line: ["//"], block: ["/*", "*/"], quotes: ['"', "'"] },
  csharp: { keywords: kw(C_LIKE + " bool int string object decimal readonly sealed partial var get set lock out ref params"), line: ["//"], block: ["/*", "*/"], quotes: ['"', "'"] },
  c: { keywords: kw(C_LIKE + " int char long short unsigned signed double float struct union typedef extern register volatile include define"), line: ["//"], block: ["/*", "*/"], quotes: ['"', "'"] },
  cpp: { keywords: kw(C_LIKE + " int char long bool auto std include define constexpr nullptr"), line: ["//"], block: ["/*", "*/"], quotes: ['"', "'"] },
  rust: { keywords: kw(C_LIKE + " fn let mut impl trait pub crate mod use match loop where self Self ref move unsafe dyn Some None Ok Err"), line: ["//"], block: ["/*", "*/"], quotes: ['"'] },
  swift: { keywords: kw(C_LIKE + " func let var guard protocol extension self Self init deinit inout"), line: ["//"], block: ["/*", "*/"], quotes: ['"'] },
  scala: { keywords: kw(C_LIKE + " def val object trait case match implicit lazy sealed"), line: ["//"], block: ["/*", "*/"], quotes: ['"', "'"] },
  php: { keywords: kw(C_LIKE + " echo print function array isset unset empty require_once include_once foreach as elseif endif"), line: ["//", "#"], block: ["/*", "*/"], quotes: ['"', "'"] },
  python: {
    keywords: kw("and as assert async await break class continue def del elif else except False finally for from global if import in is lambda None nonlocal not or pass raise return True try while with yield self print"),
    line: ["#"],
    quotes: ['"', "'"],
    multiQuotes: ['"""', "'''"],
  },
  ruby: { keywords: kw("def end if elsif else unless while until for in do return class module self nil true false begin rescue ensure yield require puts attr_accessor"), line: ["#"], quotes: ['"', "'"] },
  shell: { keywords: kw("if then else elif fi for in do done while case esac function return export local echo exit set unset"), line: ["#"], quotes: ['"', "'"] },
  powershell: { keywords: kw("if else elseif foreach for while function return param begin process end try catch finally throw"), line: ["#"], block: ["<#", "#>"], quotes: ['"', "'"] },
  sql: { keywords: kw("select from where and or not insert into values update set delete create table drop alter join left right inner outer on group by order having limit offset union as distinct null is in like exists case when then else end"), line: ["--"], block: ["/*", "*/"], quotes: ["'", '"'] },
  yaml: { keywords: kw("true false null yes no on off"), line: ["#"], quotes: ['"', "'"] },
  hcl: { keywords: kw("resource data variable output module provider locals terraform true false null for in if"), line: ["#", "//"], block: ["/*", "*/"], quotes: ['"'] },
  dockerfile: { keywords: kw("FROM RUN CMD LABEL EXPOSE ENV ADD COPY ENTRYPOINT VOLUME USER WORKDIR ARG ONBUILD STOPSIGNAL HEALTHCHECK SHELL AS"), line: ["#"], quotes: ['"', "'"] },
  groovy: { keywords: kw(C_LIKE + " def"), line: ["//"], block: ["/*", "*/"], quotes: ['"', "'"] },
  json: { keywords: kw("true false null"), quotes: ['"'] },
  xml: { keywords: kw(""), block: ["<!--", "-->"], quotes: ['"', "'"] },
  html: { keywords: kw(""), block: ["<!--", "-->"], quotes: ['"', "'"] },
  text: { keywords: kw(""), quotes: [] },
};

export type HighlightState = { inBlock?: string; inString?: string };

const isIdentStart = (c: string) => /[A-Za-z_$]/.test(c);
const isIdent = (c: string) => /[A-Za-z0-9_$]/.test(c);

/** Tokenizes one line; returns the tokens and the state for the next line. */
export function highlightLine(line: string, language: string, state: HighlightState = {}): { tokens: Token[]; state: HighlightState } {
  const def = langs[language] ?? langs.text!;
  const tokens: Token[] = [];
  const push = (kind: TokenKind, text: string) => {
    if (!text) return;
    const last = tokens[tokens.length - 1];
    // Identifiers stay separate tokens so the viewer can make them clickable.
    const word = (t: string) => /^[A-Za-z_$][\w$]*$/.test(t);
    if (last && last.kind === kind && !(kind === "plain" && (word(text) || word(last.text)))) last.text += text;
    else tokens.push({ kind, text });
  };
  let i = 0;
  const next: HighlightState = {};
  // Continue a block comment or multi-line string from the previous line.
  if (state.inBlock) {
    const end = line.indexOf(state.inBlock);
    if (end < 0) {
      push("com", line);
      return { tokens, state: { inBlock: state.inBlock } };
    }
    push("com", line.slice(0, end + state.inBlock.length));
    i = end + state.inBlock.length;
  } else if (state.inString) {
    const end = line.indexOf(state.inString);
    if (end < 0) {
      push("str", line);
      return { tokens, state: { inString: state.inString } };
    }
    push("str", line.slice(0, end + state.inString.length));
    i = end + state.inString.length;
  }
  while (i < line.length) {
    const rest = line.slice(i);
    if (def.line?.some((p) => rest.startsWith(p))) {
      push("com", rest);
      break;
    }
    if (def.block && rest.startsWith(def.block[0])) {
      const end = line.indexOf(def.block[1], i + def.block[0].length);
      if (end < 0) {
        push("com", rest);
        next.inBlock = def.block[1];
        break;
      }
      push("com", line.slice(i, end + def.block[1].length));
      i = end + def.block[1].length;
      continue;
    }
    const mq = def.multiQuotes?.find((q) => rest.startsWith(q));
    if (mq) {
      const end = line.indexOf(mq, i + mq.length);
      if (end < 0) {
        push("str", rest);
        next.inString = mq;
        break;
      }
      push("str", line.slice(i, end + mq.length));
      i = end + mq.length;
      continue;
    }
    const c = line[i]!;
    if (def.quotes.includes(c)) {
      let j = i + 1;
      while (j < line.length && line[j] !== c) j += line[j] === "\\" ? 2 : 1;
      if (j >= line.length && c === "`") {
        push("str", rest);
        next.inString = "`";
        break;
      }
      push("str", line.slice(i, Math.min(j + 1, line.length)));
      i = j + 1;
      continue;
    }
    if (/[0-9]/.test(c) && (i === 0 || !isIdent(line[i - 1]!))) {
      const m = /^(0x[0-9a-fA-F_]+|[0-9][0-9_]*(\.[0-9_]+)?([eE][+-]?[0-9]+)?)/.exec(rest);
      if (m) {
        push("num", m[0]);
        i += m[0].length;
        continue;
      }
    }
    if (isIdentStart(c)) {
      let j = i + 1;
      while (j < line.length && isIdent(line[j]!)) j++;
      const word = line.slice(i, j);
      const lower = language === "sql" ? word.toLowerCase() : word;
      if (def.keywords.has(lower)) push("kw", word);
      else if (line[j] === "(") push("fn", word);
      else if (/^[A-Z][a-z0-9]/.test(word)) push("type", word);
      else push("plain", word);
      i = j;
      continue;
    }
    push("plain", c);
    i++;
  }
  return { tokens, state: next };
}

/** Tokenizes a whole file (state carried between lines). */
export function highlightLines(lines: string[], language: string): Token[][] {
  let state: HighlightState = {};
  return lines.map((l) => {
    const r = highlightLine(l, language, state);
    state = r.state;
    return r.tokens;
  });
}

/** Function / method definitions in a file, for navigation. */
export function findSymbols(lines: string[]): { name: string; line: number }[] {
  const patterns = [
    /^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(/, // Go
    /^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/, // Python
    /^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(/, // JS function
    /^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>/, // arrow
    /^\s*(?:public|private|protected|internal|static|final|abstract|synchronized|override|async|virtual|\s)*[\w<>[\],.? ]+\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*(?:throws [\w., ]+)?\s*\{?\s*$/, // Java/C#
    /^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)/, // Rust
    /^\s*fun\s+(?:<[^>]+>\s*)?([A-Za-z_]\w*)\s*\(/, // Kotlin
    /^\s*def\s+(?:self\.)?([A-Za-z_]\w*[?!]?)/, // Ruby
    /^\s*(?:public\s+|private\s+|protected\s+|static\s+)*function\s+([A-Za-z_]\w*)\s*\(/, // PHP
    /^\s*class\s+([A-Za-z_]\w*)/,
  ];
  const skip = new Set(["if", "for", "while", "switch", "catch", "return", "new", "else"]);
  const out: { name: string; line: number }[] = [];
  lines.forEach((l, i) => {
    for (const re of patterns) {
      const m = re.exec(l);
      if (m?.[1] && !skip.has(m[1])) {
        out.push({ name: m[1], line: i + 1 });
        break;
      }
    }
  });
  return out;
}

/** Lines (1-based) where identifier appears as a whole word. */
export function findReferences(lines: string[], ident: string): number[] {
  if (!/^[A-Za-z_$][\w$]*$/.test(ident)) return [];
  const re = new RegExp(`(^|[^\\w$])${ident.replace(/\$/g, "\\$")}(?![\\w$])`);
  const out: number[] = [];
  lines.forEach((l, i) => {
    if (re.test(l)) out.push(i + 1);
  });
  return out;
}
