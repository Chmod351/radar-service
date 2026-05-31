import type { OpenPort } from "../../../../core/entities/types";
import { PROTOCOLS } from "../../../../shared/utils/const";



export function parseNmapOutput(stdout: string): OpenPort[] {
  const ports: OpenPort[] = [];
  const lines = stdout.split("\n");

  for (const line of lines) {
    const match = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(.+)$/);
    if (match ) {
      const portNum = parseInt(match[1] || "0", 10);
      const transportStr = (match[2] || "").toLowerCase(); 
      const fullServiceString = match[3] ? match[3].trim() : "";
      
      const shards=fullServiceString ? fullServiceString.split(/\s+/):[];
      const serviceRaw=shards && shards[0]? shards[0].toLowerCase() : "";
      const versionInfo=shards.slice(1).join(" ") || null;

      let transportId: number = PROTOCOLS.TRANSPORT.UNKNOWN;
      if (transportStr === "tcp") transportId = PROTOCOLS.TRANSPORT.TCP;
      if (transportStr === "udp") transportId = PROTOCOLS.TRANSPORT.UDP; 
      
      let appId :number= PROTOCOLS.APP.UNKNOWN;
      if (serviceRaw.includes("http")) appId = PROTOCOLS.APP.HTTP;
      if (serviceRaw.includes("ssl") || serviceRaw.includes("https")) appId = PROTOCOLS.APP.HTTPS;
      if (serviceRaw.includes("ssh")) appId = PROTOCOLS.APP.SSH;
      if (serviceRaw.includes("ftp")) appId = PROTOCOLS.APP.FTP;
      if (serviceRaw.includes("dns")) appId = PROTOCOLS.APP.DNS;
      if (serviceRaw.includes("sql") || serviceRaw.includes("db")) appId = PROTOCOLS.APP.DATABASE;

      ports.push({
        port:portNum,
        protocol: appId,
        transport:transportId,
        service:serviceRaw,
        version:versionInfo,
      });
    }
  }
  return ports;
}

