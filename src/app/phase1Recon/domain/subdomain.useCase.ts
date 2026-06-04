import { logger } from "../../../shared/systemLogger";
import { PHASES } from "../../../shared/utils/const";
import { getErrorMessage } from "../../../shared/utils/utils";
import { runSubdomainStream } from "../infra/subdomain.adapter";
import { getReconSources } from "../infra/recon.probes";
import { reconService } from "./phase1.repository";


export async function* streamAllSubdomains(target: string,scanId:number|bigint): AsyncIterable<string> {
  logger.info(PHASES.RECON, `[*] Radar activado: Escaneo paralelo para ${target}`);
  const sources=getReconSources(target);
  const emitedSubdomains = new Set<string>();
  const outputQueue: string[] = [];

  let activeSources = sources.length;
  let signalResolver: (() => void) | null = null;
  let totalFound = 0;

  sources.forEach(async (source) => {
    try {
      for await (const sub of runSubdomainStream(source.cmd, source.args)) {

        const cleanSub=sub.trim().toLowerCase();
        if (emitedSubdomains.has(cleanSub)) continue; 

        if (await reconService.processDiscovery(sub, scanId, target)) {
          emitedSubdomains.add(cleanSub);
          totalFound++;
          outputQueue.push(cleanSub);

          if (signalResolver) {
            signalResolver();
            signalResolver = null;
          }
        }
      }
    } catch (e){
      logger.error(PHASES.RECON, `ERROR en ${source.name}:`,getErrorMessage(e));
    } finally {
      activeSources--;
      if (signalResolver) {
        signalResolver();
        signalResolver = null;
      }
      logger.info(PHASES.RECON, `Fuente ${source.name} completada. Encontrados: ${totalFound} resultados.`);
    }
  });

  while (activeSources > 0 || outputQueue.length > 0) {
    if (outputQueue.length > 0) {
      yield outputQueue.shift()!;
    } else {
      await new Promise<void>((resolve) => {
        signalResolver = resolve;
      });
    }
  }

  logger.info(PHASES.RECON, "[#] Recon finalizado");
}
