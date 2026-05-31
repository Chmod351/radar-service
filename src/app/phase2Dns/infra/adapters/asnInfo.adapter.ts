
import { resolveTxt } from "node:dns/promises";


async function DNSRawResolver(query:string) {
  const records = await resolveTxt(query); 
  return records; 
} 


export async function cymruService(ip:string) {
  const revIp = ip.split(".").reverse().join(".");
  const query = `${revIp}.origin.asn.cymru.com`;
  const records =  await DNSRawResolver(query);

  const firstEntry =  records?.[0]?.[0];

  return firstEntry;
}
