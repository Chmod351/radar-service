export function isValididIp(ip:string|undefined|null) {
  if (!ip || ip === "0.0.0.0" || ip === "127.0.0.1") {
    return false;
  }
  return true;
}
