export function subdomainMapper(domain:string):string|null {

  const cleanedDomain= domain.replace(/u003e|u003c/g, "");

  if (/^[a-z0-9.-]+$/.test(cleanedDomain)) {
    return cleanedDomain;
  }
  return null;
}
