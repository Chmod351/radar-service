import { noise, USER_AGENTS } from "./data";


// ----------------
export const noiseSet = new Set(noise);
export const isRealTech = (techName: string) => !noiseSet.has(techName);
export const TARGET = Bun.argv[2]; // Esto reemplaza al TARGET="$1"
// ----------------


export function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}


export function generateBypassPayloads(url:string) {
  const bypassPayloads = [
    { name: "Base", header: null },
    { name: "X-Forwarded-For", header: "X-Forwarded-For: 127.0.0.1" },
    { name: "X-Original-URL", header: "X-Original-URL: /admin" },
    { name:"X-Forwarded-For-127",header:"X-Originating-IP:  127.0.0.1" },
    { name:"X-Remote-Ip",header:"X-Remote-IP: 127.0.0.1" },
    { name:"X-Remote-Addr",header: "X-Remote-Addr: 127.0.0.1" },
    { name:"X-Client-IP",header:"X-Client-IP: 127.0.0.1" },
    { name:"X-Host", header: "X-Host: 127.0.0.1" },
    { name:"X-Forwarded-Host",header : "X-Formwarded-Host: localhost" },
    { name: "X-Rewrite-URL", header: `X-Rewrite-URL: ${url.endsWith("/") ? url : url + "/"}`, 
    },
  ]; 

  return bypassPayloads;
}


export const getRandomAgent = () => USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)] || USER_AGENTS[0];
