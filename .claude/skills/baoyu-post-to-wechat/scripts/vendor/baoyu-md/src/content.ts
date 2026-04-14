import { Lexer } from "marked";

export type FrontmatterFields = Record<string, string>;

export function parseFrontmatter(content: string): {
  frontmatter: FrontmatterFields;
  body: string;
} {
  const match = content.match(/^\s*---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (!match) {
    return { frontmatter: {}, body: content };
  }

  const frontmatter: FrontmatterFields = {};
  const lines = match[1]!.split("\n");
  for (const line of lines) {
    const colonIdx = line.indexOf(":");
    if (colonIdx <= 0) continue;

    const key = line.slice(0, colonIdx).trim();
    const value = line.slice(colonIdx + 1).trim();
    frontmatter[key] = stripWrappingQuotes(value);
  }

  return { frontmatter, body: match[2]! };
}

export function serializeFrontmatter(frontmatter: FrontmatterFields): string {
  const entries = Object.entries(frontmatter);
  if (entries.length === 0) return "";
  return `---\n${entries.map(([key, value]) => `${key}: ${value}`).join("\n")}\n---\n`;
}

export function stripWrappingQuotes(value: string): string {
  if (!value) return value;

  const doubleQuoted = value.startsWith('"') && value.endsWith('"');
  const singleQuoted = value.startsWith("'") && value.endsWith("'");
  const cjkDoubleQuoted = value.startsWith("\u201c") && value.endsWith("\u201d");
  const cjkSingleQuoted = value.startsWith("\u2018") && value.endsWith("\u2019");

  if (doubleQuoted || singleQuoted || cjkDoubleQuoted || cjkSingleQuoted) {
    return value.slice(1, -1).trim();
  }

  return value.trim();
}

const HTML_ENTITIES: Record<string, string> = {
  amp: "&",
  apos: "'",
  gt: ">",
  lt: "<",
  nbsp: " ",
  quot: '"',
};

function decodeHtmlCodePoint(codePoint: number, fallback: string): string {
  if (!Number.isFinite(codePoint) || codePoint < 0 || codePoint > 0x10ffff) {
    return fallback;
  }
  return String.fromCodePoint(codePoint);
}

function decodeHtmlEntities(value: string): string {
  return value.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (entity, body: string) => {
    const normalized = body.toLowerCase();
    if (normalized.startsWith("#x")) {
      return decodeHtmlCodePoint(Number.parseInt(normalized.slice(2), 16), entity);
    }
    if (normalized.startsWith("#")) {
      return decodeHtmlCodePoint(Number.parseInt(normalized.slice(1), 10), entity);
    }
    return HTML_ENTITIES[normalized] ?? entity;
  });
}

export function cleanSummaryText(value: string): string {
  return decodeHtmlEntities(stripWrappingQuotes(value))
    .replace(/<script\b[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[\s\S]*?<\/style>/gi, " ")
    .replace(/<br\s*\/?>/gi, " ")
    .replace(/<\/?[a-z][a-z0-9:-]*(?:\s+[^>]*)?>/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export function toFrontmatterString(value: unknown): string | undefined {
  if (typeof value === "string") {
    return stripWrappingQuotes(value);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return undefined;
}

export function pickFirstString(
  frontmatter: Record<string, unknown>,
  keys: string[],
): string | undefined {
  for (const key of keys) {
    const value = toFrontmatterString(frontmatter[key]);
    if (value) return value;
  }
  return undefined;
}

export function extractTitleFromMarkdown(markdown: string): string {
  const tokens = Lexer.lex(markdown, { gfm: true, breaks: true });
  for (const token of tokens) {
    if (token.type !== "heading" || (token.depth !== 1 && token.depth !== 2)) continue;
    return stripWrappingQuotes(token.text);
  }
  return "";
}

export function extractSummaryFromBody(body: string, maxLen: number): string {
  const lines = body.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith("#")) continue;
    if (trimmed.startsWith("![")) continue;
    if (trimmed.startsWith(">")) continue;
    if (trimmed.startsWith("-") || trimmed.startsWith("*")) continue;
    if (/^\d+\./.test(trimmed)) continue;
    if (trimmed.startsWith("```")) continue;

    const cleanText = trimmed
      .replace(/\*\*(.+?)\*\*/g, "$1")
      .replace(/\*(.+?)\*/g, "$1")
      .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
      .replace(/`([^`]+)`/g, "$1");
    const summaryText = cleanSummaryText(cleanText);

    if (summaryText.length > 20) {
      if (summaryText.length <= maxLen) return summaryText;
      return `${summaryText.slice(0, maxLen - 3)}...`;
    }
  }

  return "";
}
