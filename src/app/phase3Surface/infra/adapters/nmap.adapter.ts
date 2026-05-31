import { execa } from "execa";
/**
     * Argumentos:
     * -F: Escanea los 100 puertos más comunes (muy rápido).
     * --open: Solo muestra puertos abiertos.
     * -T4: Agresividad de tiempo (nivel 4 de 5, ideal para escaneos rápidos).
     * -n: No hace resolución DNS inversa (ya la hicimos nosotros).
     *  -sV Service Version detection 
     *  --version-intensity 0 Intensidad mínima para no mandar demasiados probes
     *  --script=banner Solo pide el banner
     *  -oX Output en formato xml
     */


export async function getPortsAvailable(target:string) {
  const { stdout } = await execa("nmap", ["-F", "--open", "-T3","-n","-sV","--version-intensity","0","--script=banner", target], { 
    timeout: 120000,
  });  
  return stdout;
 
}
