import type { BypassAttempt } from "../../core/entities/types";
import { logger } from "../../shared/systemLogger";

export function compareSize(attempts:BypassAttempt[],status:number,url:string,size:string|undefined,payload:string|null,s:number) {

  if (attempts.length > 1 && status !== 0) {
    const baseSize =attempts && attempts[0]? attempts[0].size:0;

    if (Math.abs(baseSize - s) > 50) { // Umbral de 50 bytes para evitar ruido de headers
      logger.warn("BYPASS", `Variación detectada en ${payload} (${size} bytes) contra ${url}`);
    }
  }
}
