import type { HttpIntel } from "../../../../core/entities/types";
import { PROTOCOLS } from "../../../../shared/utils/const";

export function httpIntelBuilder(
  headers:
    {[k:string]:string}, 
  url:string, 
  status:number,
  attempts:
    {method:string,
      header:null|string,
      status:number, 
      size:number, 
      timestamp:string}[],
  cookies:boolean,
):HttpIntel {
  return {
    protocol: url.startsWith("https") ? PROTOCOLS.APP.HTTPS : PROTOCOLS.APP.HTTP,
    status,
    security: {
      hsts: !!headers["strict-transport-security"],
      csp: !!headers["content-security-policy"],
      xfo: !!headers["x-frame-options"],
      nosniff: !!headers["x-content-type-options"],
    },
    server: headers["server"] || null,
    poweredBy: headers["x-powered-by"] || headers["server"] || null,
    cookies,
    attempts,
  };
}

