const RAW_NAME = /^[\p{L}\p{M}\p{N}.-]+$/u;
const ASCII_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

/** Canonical ASCII DNS name, without a trailing dot. Throws for invalid input. */
export function normalizeDnsName(input) {
  if (typeof input !== "string")
    throw new TypeError("DNS name must be a string");

  let value = input.trim();
  if (value.endsWith(".")) value = value.slice(0, -1);
  if (!value || !RAW_NAME.test(value)) throw new TypeError("Invalid DNS name");

  for (const character of value) {
    if (
      character.codePointAt(0) > 127 &&
      /^[\x00-\x7f]+$/.test(character.normalize("NFC"))
    ) {
      throw new TypeError("Ambiguous DNS name");
    }
  }

  // Reject compatibility characters that URL/IDNA could silently map onto an
  // authorized ASCII spelling (for example fullwidth Latin or Kelvin sign).
  const nfc = value.normalize("NFC");
  if (nfc.normalize("NFKC") !== nfc) throw new TypeError("Ambiguous DNS name");

  const labels = nfc.split(".");
  if (labels.some((label) => label.length === 0))
    throw new TypeError("Empty DNS label");

  const asciiLabels = labels.map((label) => {
    let ascii;
    try {
      // A nonnumeric suffix prevents URL's special IPv4 host parser from
      // changing a numeric DNS label. URL supplies platform IDNA conversion.
      ascii = new URL(`https://${label}.invalid/`).hostname.slice(
        0,
        -".invalid".length,
      );
    } catch {
      throw new TypeError("Invalid IDN label");
    }
    if (ascii.length < 1 || ascii.length > 63 || !ASCII_LABEL.test(ascii)) {
      throw new TypeError("Invalid DNS label");
    }
    return ascii;
  });

  const canonical = asciiLabels.join(".");
  if (canonical.length > 253) throw new TypeError("DNS name too long");
  return canonical;
}

/** Canonical SRV owner with exactly two service labels before a DNS hostname. */
export function normalizeSrvOwner(input) {
  if (typeof input !== "string") throw new TypeError("Invalid SRV owner");
  const match = /^(_[a-z0-9-]{1,62})\.(_(?:tcp|udp))\.(.+)$/i.exec(input);
  if (!match) throw new TypeError("Invalid SRV owner");
  return `${match[1].toLowerCase()}.${match[2].toLowerCase()}.${normalizeDnsName(match[3])}`;
}

export function isStrictDescendant(name, root) {
  return normalizeDnsName(name).endsWith(`.${normalizeDnsName(root)}`);
}

/** Select the longest boundary-matching configured zone, including disabled zones. */
export function selectConfiguredZone(input, zones) {
  const name = normalizeDnsName(input);
  if (!Array.isArray(zones)) throw new TypeError("Zones must be an array");
  let selected = null;
  for (const zone of zones) {
    const zoneName = normalizeDnsName(zone.name);
    if (name === zoneName || isStrictDescendant(name, zoneName)) {
      if (!selected || zoneName.length > selected.name.length) {
        selected = { ...zone, name: zoneName };
      }
    }
  }
  return selected;
}
