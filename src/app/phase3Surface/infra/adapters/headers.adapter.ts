import { execa } from "execa";
import { getRandomAgent } from "../../../../shared/utils/utils";

export async function  fetchTargetWithTimeout (url:string) {

  const agent = getRandomAgent();

  const controller = new AbortController();

  const id = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(url, {
      method: "GET",
      headers: { "User-Agent": agent } as Record<string, string>,
      redirect: "follow",
      signal: controller.signal,
    });

    return response;
  } finally {
    clearTimeout(id);
  }
    
}


export async function fetchFallback (url:string) {
  const agent = getRandomAgent() ?? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0";
  const { stdout, stderr } = await execa("curl", [
    "-I",                      // Solo headers
    "-s",                      // Silent
    "-L",                      // Seguir redirecciones
    "-k",                      
    "--max-time", "10",
    "-A", agent,
    url,
  ], { reject: false });
  if (!stdout) {
    throw new Error(`Curl no devolvio headers:${stderr}`);
  }
  return stdout; 
}

export async function tryFuff(url:string,payload:string|null) {

  const agent :string =getRandomAgent() ?? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0";
  const args = [
    "-s", "-L", "-k",
    "--max-time", "10",
    "-A", agent,
    "-o", "/dev/null", // sin el body en el stdout
    "-w", "%{http_code},%{size_download}", // formateamos el codigo y el tamaño
    url,
  ];

  if (payload) {
    args.push("-H", payload);
  }

  const { stdout } = await execa("curl", args, { reject: false });
  return stdout;
}
