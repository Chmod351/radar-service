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
  const headersRaw = stdout.split(/\r?\n/);
  let statusLineIndex = -1;

  for (let index = 0; index < headersRaw.length; index++) {
    if (/^HTTP\/\S+\s+\d{3}/i.test(headersRaw[index] || "")) statusLineIndex = index;
  }

  const headers: Record<string,string>={}; 
  const statusLine = statusLineIndex >= 0 ? headersRaw[statusLineIndex] || "" : "";

  for (let index = statusLineIndex + 1; index < headersRaw.length && headersRaw[index]; index++) {
    const line = headersRaw[index] || "";
    const parts = line.split(": ");
    if (parts.length >= 2 && parts[0]) {
      const key = parts[0].toLowerCase();
      const value = parts.slice(1).join(": ").trim();
      headers[key] = value;
    }
  }

  const statusMatch = statusLine.match(/^HTTP\/\S+\s+(\d{3})/i);
  const statusCode = statusMatch ? Number.parseInt(statusMatch[1] || "0", 10) : 0;

  return { statusCode,headers };
    
}
