import { SCAN_STATUS_COMPLETED, type AnalyzedTarget, type EventPublisher } from "../../core/entities/types";
import { isOsintMode, scanId } from "../../infra/enviromentVariables";
import { withRetry } from "../../shared/retry";
import { logger } from "../../shared/systemLogger";
import { PHASES, SENSORS } from "../../shared/utils/const";
import { getErrorMessage } from "../../shared/utils/utils";
import { streamAllSubdomains } from "../phase1Recon/domain/subdomain.useCase";
import { dnsPhaseStream } from "../phase2Dns/domain/infraResolver.useCase";
import { fingerprintingPhase } from "../phase3Surface/domain/serverFingerprinting.useCase";
import { scanPortsSafe } from "../phase3Surface/serverFingerPrintingProbe";
import { normalizeRadarTarget } from "./orchestrator.mapper";

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

          await this.eventPublisher.publish("host:discovered", "processing", normalizeRadarTarget(result, scanId));
          logger.info("EVENT ORCHESTRATOR HOST DISCOVERED:", result.host || sub);

          if (!isOsintMode && result.action === SENSORS.ACTION.SKIP) {
            await this.eventPublisher.publish("host:updated", "partial", normalizeRadarTarget(result, scanId));
            return;
          }

          // Fingerprinting web: se ejecuta para cada hostname, también en OSINT.
          const webData = await fingerprintingPhase(result as AnalyzedTarget, scanId);
          let finalData: AnalyzedTarget = webData;

          // Nmap: solamente en Deep, deduplicado por IP.
          if (!isOsintMode && finalData && finalData.ip) {
            if (!scannedIps.has(result.ip)) {
              const scanPromise = (async () => {
                const openPorts = await withRetry(
                  "nmap-scan",
                  () => scanPortsSafe(finalData.ip),
                  { retries: 2, delay: 2000 },
                );

                return {
                  ...webData,
                  open_ports: openPorts,
                };
              })();
              scannedIps.set(result.ip, scanPromise);
              finalData = await scanPromise;
            } else {
              logger.debug(PHASES.ORCHESTRATOR, `Omitiendo Nmap para ${result.host}. IP ${result.ip} ya está cubierta.`);

              const infrastructureData = await scannedIps.get(result.ip);

              finalData = {
                ...webData,
                open_ports: infrastructureData?.open_ports || [],
              };
            }
          }

          await this.eventPublisher.publish("host:updated", "success", normalizeRadarTarget(finalData, scanId));
          logger.info("EVENT ORCHESTRATOR UPDATE:", finalData.host || result.host || "unknown");

        } catch (e: unknown) {
          logger.error(PHASES.ORCHESTRATOR, getErrorMessage(e));
        }
      })();

      activeWorkers.add(worker);
      allTasks.push(worker);
      worker.finally(() => activeWorkers.delete(worker));
    }

    await Promise.all(allTasks);

    await this.eventPublisher.publish("phase-1", SCAN_STATUS_COMPLETED, {
      scanId,
      id: 0,
      status: SCAN_STATUS_COMPLETED,
      total_subdomains_found: totalOfSubs,
      total_stages_executed: isOsintMode? 2 : 3,
    });

    logger.info("EVENT ORCHESTRATOR: Phase 1", SCAN_STATUS_COMPLETED);

    await this.eventPublisher.publish("scan:finished", SCAN_STATUS_COMPLETED, {
      scanId,
      id: 0,
      status: SCAN_STATUS_COMPLETED,
      total_stages_executed: isOsintMode? 2 : 3,
      total_subdomains_found: totalOfSubs,
    });

    logger.info(`EVENT ORCHESTRATOR:${isOsintMode ? "Phase 2" :"Phase 3" }`,SCAN_STATUS_COMPLETED);
  }
}
