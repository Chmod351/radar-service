import type { WebMetadata } from "../../../../core/entities/types";

export function httpParser(stdout:string,host:string): WebMetadata {

  if (!stdout.trim()) throw new Error("No web response");
  const data = JSON.parse(stdout);
   
     
  return {
    url: data.url || `http://${host}`,
    status_code: data.status_code || data["status-code"] || 0,
    title: data.title || null,
    webserver: data.web_server || data.server || data.webserver || null,
    cdn:null,
  }; 
}

export function bypassAttemptParser (stdout:string) {
  const [statusCode, size] = stdout.split(",");
  const status =statusCode? parseInt(statusCode) : 0;
  const s =size? parseInt(size) : 0; 

  return { status,s ,size };
}

export function headersFormatter(stdout:string) {
  const headersRaw = stdout.split("\r\n");
  const headers: Record<string,string>={}; 
    
  headersRaw.forEach(line => {
    const parts = line.split(": ");
    if (parts.length >= 2 && parts[0]) {
      const key = parts[0].toLowerCase();
      const value = parts.slice(1).join(": ").trim();
      headers[key] = value;
    }
  });
  const statusLine=headersRaw[0];
  const statusParts = statusLine ? statusLine.split(" "): [];
  const statusCode = statusParts.length>=2 && statusParts[1] ? parseInt(statusParts[1]):0;

  return { statusCode,headers };
    
}
