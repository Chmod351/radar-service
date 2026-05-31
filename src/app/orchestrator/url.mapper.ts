export function normalizeScanTarget(input: string): string {
  if (!input) return "";

  let clean = input.trim().toLowerCase();
  clean = clean.replace(/^(?:f|ht)tps?:\/\//, "");

 
  const [beforeSlash] = clean.split("/");
  const [beforeQuery] = (beforeSlash || "").split("?");
  const [domain] = (beforeQuery || "").split(":");

  clean = (domain || "").replace(/^www\./, "");
  clean = clean.replace(/^www\./, "");

  return clean;
}
