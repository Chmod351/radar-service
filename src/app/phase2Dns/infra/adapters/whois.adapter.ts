import { execa } from "execa";

export async function getWhois(root:string):Promise<string> {
  const { stdout } = await execa("whois", [root], { 
    timeout: 8000,
    reject: true, 
  });
  return stdout;    
}
