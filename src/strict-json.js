// A bounded structural scan before JSON.parse. JSON.parse alone silently accepts
// duplicate object keys, which is unsafe for both authorization claims and API data.
export function parseStrictJson(
  source,
  { maxBytes = 65536, maxDepth = 24, maxNodes = 2048 } = {},
) {
  if (
    typeof source !== "string" ||
    new TextEncoder().encode(source).length > maxBytes
  )
    throw new TypeError("Invalid JSON size");
  let i = 0;
  let nodes = 0;
  const whitespace = () => {
    while (/\s/.test(source[i] ?? "") && i < source.length) i++;
  };
  const string = () => {
    const start = i++;
    while (i < source.length) {
      if (source[i] === '"') return JSON.parse(source.slice(start, ++i));
      if (source[i] === "\\") i++;
      i++;
    }
    throw new TypeError("Unterminated JSON string");
  };
  const value = (depth) => {
    if (++nodes > maxNodes || depth > maxDepth)
      throw new TypeError("JSON complexity limit");
    whitespace();
    if (source[i] === '"') {
      string();
      return;
    }
    if (source[i] === "{") {
      i++;
      whitespace();
      const keys = new Set();
      if (source[i] === "}") {
        i++;
        return;
      }
      while (true) {
        whitespace();
        if (source[i] !== '"') throw new TypeError("Invalid JSON object");
        const key = string();
        if (keys.has(key)) throw new TypeError("Duplicate JSON key");
        keys.add(key);
        whitespace();
        if (source[i++] !== ":") throw new TypeError("Invalid JSON object");
        value(depth + 1);
        whitespace();
        const separator = source[i++];
        if (separator === "}") return;
        if (separator !== ",") throw new TypeError("Invalid JSON object");
      }
    }
    if (source[i] === "[") {
      i++;
      whitespace();
      if (source[i] === "]") {
        i++;
        return;
      }
      while (true) {
        value(depth + 1);
        whitespace();
        const separator = source[i++];
        if (separator === "]") return;
        if (separator !== ",") throw new TypeError("Invalid JSON array");
      }
    }
    const match =
      /^(?:-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/.exec(
        source.slice(i),
      );
    if (!match) throw new TypeError("Invalid JSON value");
    i += match[0].length;
  };
  value(0);
  whitespace();
  if (i !== source.length) throw new TypeError("Invalid JSON suffix");
  return JSON.parse(source);
}
