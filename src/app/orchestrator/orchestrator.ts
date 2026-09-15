import type { AnalyzedTarget, EventPublisher } from "../../core/entities/types";
import { logger } from "../../shared/systemLogger";
import { PHASES } from "../../shared/utils/const";
import { getErrorMessage } from "../../shared/utils/utils";
import { streamAllSubdomains } from "../phase1Recon/domain/subdomain.useCase";
import { dnsPhaseStream } from "../phase2Dns/domain/infraResolver.useCase";
import { fingerprintingPhase } from "../phase3Surface/domain/serverFingerprinting.useCase";
import { scanId } from "../../infra/enviromentVariables";
import { normalizeRadarTarget } from "./orchestrator.mapper";
import { isOsintMode } from "../../infra/enviromentVariables";

export class Orchestrator {
  constructor(private eventPublisher: EventPublisher) { }
  private concurrencyLimit = 4;

  async start(target: string) {
    const activeWorkers = new Set<Promise<void>>();
    const allTasks: Promise<void>[] = [];
    const scannedIps = new Map<string, Promise<AnalyzedTarget>>();
    let totalOfSubs = 0;

    logger.info(PHASES.ORCHESTRATOR, `Iniciando escaneo... [Modo OSINT: ${isOsintMode}]`);
    const subdomainStream = streamAllSubdomains(target, scanId);

    for await (const sub of subdomainStream) {
      totalOfSubs++;

      if (activeWorkers.size >= this.concurrencyLimit) {
        await Promise.race(activeWorkers);
      }

      const worker = (async () => {
        try {
          const result = await dnsPhaseStream(sub, scanId);
          if (!result || !result.ip || result.ip === "N/A" || result.ip === "0.0.0.0") return;

          this.eventPublisher.publish("host:discovered", "processing", normalizeRadarTarget(result, scanId));

          if (isOsintMode) {
            this.eventPublisher.publish("host:updated", "success", normalizeRadarTarget(result, scanId));
            return; 
          }

          if (!scannedIps.has(result.ip)) {
            const scanPromise = (async () => {
              return await fingerprintingPhase(result as AnalyzedTarget, scanId);
            })();

            scannedIps.set(result.ip, scanPromise);
            const finalData = await scanPromise;
            this.eventPublisher.publish("host:updated", "success", normalizeRadarTarget(finalData, scanId));
          } else {
            logger.debug(PHASES.ORCHESTRATOR, `Omitiendo Nmap para ${result.host}. IP ${result.ip} ya está cubierta.`);
            const fatherData = await scannedIps.get(result.ip);

            if (fatherData) {
              const updatedChild = {
                ...(result as AnalyzedTarget),
                open_ports: fatherData.open_ports || [],
                webserver: fatherData.webserver || result.webserver || null,
                http_intel: fatherData.http_intel,
                http_stack: fatherData.http_stack,
                whois: fatherData.whois,
                whois_raw: fatherData.whois_raw
              };
              this.eventPublisher.publish("host:updated", "success", normalizeRadarTarget(updatedChild, scanId));
            }
          }
        } catch (e: unknown) {
          logger.error(PHASES.ORCHESTRATOR, getErrorMessage(e));
        }
      })();

      activeWorkers.add(worker);
      allTasks.push(worker);
      worker.finally(() => activeWorkers.delete(worker));
    }

    await Promise.all(allTasks);

    this.eventPublisher.publish("phase-1", "completed", {
      scanId,
      id: 0,
      status: "completed",
      total_subdomains_found: totalOfSubs,
      total_stages_executed: isOsintMode ? 2 : 3,
    });

    this.eventPublisher.publish("scan:finished", "completed", {
      scanId,
      id: 0,
      status: "completed",
      total_stages_executed: isOsintMode ? 2 : 3,
      total_subdomains_found: totalOfSubs,
    });
  }
}
