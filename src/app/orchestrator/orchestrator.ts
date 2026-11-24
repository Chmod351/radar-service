import {
  SCAN_STATUS_COMPLETED,
  type AnalyzedTarget,
  type EventPublisher,
} from "../../core/entities/types";

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

type OpenPorts = Awaited<ReturnType<typeof scanPortsSafe>>;
export class Orchestrator {
  constructor(private eventPublisher: EventPublisher) { }

  private concurrencyLimit = 4;

  async start(target: string): Promise<void> {
    const activeWorkers = new Set<Promise<void>>();
    const allTasks: Promise<void>[] = [];

    // Compartido entre todos los workers del escaneo.
    // Solamente se cachean resultados de Nmap, nunca datos HTTP.
    const scannedIps = new Map<string, Promise<OpenPorts>>();

    let totalOfSubs = 0;

    logger.info(
      PHASES.ORCHESTRATOR,
      `Iniciando escaneo... [Modo OSINT: ${isOsintMode}]`,
    );

    const subdomainStream = streamAllSubdomains(target, scanId);

    for await (const sub of subdomainStream) {
      totalOfSubs++;

      if (activeWorkers.size >= this.concurrencyLimit) {
        await Promise.race(activeWorkers);
      }

      const worker = this.processHost(sub, scannedIps).catch((error: unknown) => {
        logger.error(
          PHASES.ORCHESTRATOR,
          `Error no controlado procesando ${sub}: ${getErrorMessage(error)}`,
        );
      });

      activeWorkers.add(worker);
      allTasks.push(worker);

      void worker.finally(() => activeWorkers.delete(worker));
    }

    await Promise.all(allTasks);

    await this.eventPublisher.publish("phase-1", SCAN_STATUS_COMPLETED, {
      scanId,
      id: 0,
      status: SCAN_STATUS_COMPLETED,
      total_subdomains_found: totalOfSubs,
      total_stages_executed: isOsintMode ? 2 : 3,
    });

    logger.info("EVENT ORCHESTRATOR: Phase 1", SCAN_STATUS_COMPLETED);

    await this.eventPublisher.publish("scan:finished", SCAN_STATUS_COMPLETED, {
      scanId,
      id: 0,
      status: SCAN_STATUS_COMPLETED,
      total_stages_executed: isOsintMode ? 2 : 3,
      total_subdomains_found: totalOfSubs,
    });

    logger.info(
      `EVENT ORCHESTRATOR: ${isOsintMode ? "Phase 2" : "Phase 3"}`,
      SCAN_STATUS_COMPLETED,
    );
  }


  private async processHost(
    sub: string,
    scannedIps: Map<string, Promise<OpenPorts>>,
  ): Promise<void> {
    // PHASE 2: DNS / ASN

    let targetData: AnalyzedTarget | undefined;

    try {
      const result = await dnsPhaseStream(sub, scanId);

      if (
        !result ||
        !result.ip ||
        result.ip === "N/A" ||
        result.ip === "0.0.0.0"
      ) {
        return;
      }

      targetData = result as AnalyzedTarget;
    } catch (error: unknown) {
      logger.error(
        PHASES.ORCHESTRATOR,
        `Error DNS/ASN para ${sub}: ${getErrorMessage(error)}`,
      );
      return;
    }

    await this.eventPublisher.publish(
      "host:discovered",
      "processing",
      normalizeRadarTarget(targetData, scanId),
    );

    // PHASE 2: WEB FINGERPRINTING

    let webData: AnalyzedTarget;

    try {
      webData = await fingerprintingPhase(targetData, scanId);
    } catch (error: unknown) {
      logger.error(
        PHASES.ORCHESTRATOR,
        `Error fingerprinting para ${sub}: ${getErrorMessage(error)}`,
      );

      const failedData: AnalyzedTarget = {
        ...targetData,
        analysis_phase: 2,
        analysis_state: "failed",
        analysis_confidence: "low",
        evidence: {
          ...(targetData.evidence ?? {
            dns: true,
            asn: false,
            http: false,
            whois: false,
            nmap: false,
            whatweb: false,
          }),
          http: false,
          nmap: false,
          whatweb: false,
        },
      };

      await this.eventPublisher.publish(
        "host:updated",
        "failed",
        normalizeRadarTarget(failedData, scanId),
      );

      return;
    }

    const shouldSkipActiveProbe =
      !isOsintMode && webData.action === SENSORS.ACTION.SKIP;

    const phase2State =
      webData.analysis_state === "failed"
        ? "failed"
        : isOsintMode || shouldSkipActiveProbe
          ? "complete"
          : "partial";

    const phase2Data: AnalyzedTarget = {
      ...webData,
      analysis_phase: 2,
      analysis_state: phase2State,
    };

    // Publicar fase 2 antes de ejecutar cualquier prueba activa.
    await this.eventPublisher.publish(
      "host:updated",
      phase2State === "complete"
        ? "success"
        : phase2State === "failed"
          ? "failed"
          : "partial",
      normalizeRadarTarget(phase2Data, scanId),
    );

    logger.info(
      PHASES.ORCHESTRATOR,
      `Fase 2 finalizada para ${webData.host}: ${phase2State}`,
    );

    if (phase2State === "failed" || isOsintMode || shouldSkipActiveProbe) {
      return;
    }

    // PHASE 3: ACTIVE PROBING

    const phase3Started: AnalyzedTarget = {
      ...phase2Data,
      analysis_phase: 3,
      analysis_state: "partial",
      evidence: {
        ...(phase2Data.evidence ?? {
          dns: false,
          asn: false,
          http: false,
          whois: false,
          nmap: false,
          whatweb: false,
        }),
        nmap: false,
      },
    };

    await this.eventPublisher.publish(
      "host:updated",
      "processing",
      normalizeRadarTarget(phase3Started, scanId),
    );

    let phase3Data: AnalyzedTarget;

    try {
      phase3Data = await runActiveProbePhase(
        phase3Started,
        scannedIps,
      );
    } catch (error: unknown) {
      logger.error(
        PHASES.ORCHESTRATOR,
        `Error Nmap para ${webData.host}: ${getErrorMessage(error)}`,
      );

      const failedData: AnalyzedTarget = {
        ...phase3Started,
        analysis_phase: 3,
        analysis_state: "failed",
        analysis_confidence: "low",
        evidence: {
          asn: Boolean(phase2Data.evidence?.asn),
          dns: Boolean(phase2Data.evidence?.dns),
          http: Boolean(phase2Data.evidence?.http),
          whois: Boolean(phase2Data.evidence?.whois),
          whatweb: Boolean(phase2Data.evidence?.whatweb),
          nmap: false,
        },
      };

      await this.eventPublisher.publish(
        "host:updated",
        "failed",
        normalizeRadarTarget(failedData, scanId),
      );

      return;
    }

    await this.eventPublisher.publish(
      "host:updated",
      "success",
      normalizeRadarTarget(phase3Data, scanId),
    );

    logger.info(
      PHASES.ORCHESTRATOR,
      `Fase 3 finalizada para ${phase3Data.host}`,
    );
  }
}
/**
 * Ejecuta Nmap para una IP.
 *
 * La Promise se almacena antes de esperar su resolución para evitar
 * que dos workers ejecuten Nmap simultáneamente contra la misma IP.
 *
 * Los resultados HTTP nunca se comparten entre hostnames.
 */
async function runActiveProbePhase(
  webData: AnalyzedTarget,
  scannedIps: Map<string, Promise<OpenPorts>>,
): Promise<AnalyzedTarget> {
  const ip = webData.ip;

  if (!ip) {
    throw new Error(`No hay IP disponible para ejecutar Nmap: ${webData.host}`);
  }

  let scanPromise = scannedIps.get(ip);

  if (!scanPromise) {
    scanPromise = withRetry(
      "nmap-scan",
      () => scanPortsSafe(ip),
      { retries: 2, delay: 2000 },
    );

    scannedIps.set(ip, scanPromise);
  } else {
    logger.debug(
      PHASES.ORCHESTRATOR,
      `Reutilizando resultado Nmap para ${webData.host}. IP ${ip} ya está cubierta.`,
    );
  }

  try {
    const openPorts = await scanPromise;

    return {
      ...webData,
      open_ports: openPorts,
      analysis_phase: 3,
      analysis_state: "complete",
      evidence: {
        ...(webData.evidence ?? {
          dns: false,
          asn: false,
          http: false,
          whois: false,
          nmap: false,
          whatweb: false,
        }),
        nmap: true,
      },
    };
  } catch (error: unknown) {
    // Permite que otro hostname con la misma IP vuelva a intentar Nmap.
    if (scannedIps.get(ip) === scanPromise) {
      scannedIps.delete(ip);
    }

    throw error;
  }
}