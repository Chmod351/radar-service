import type { AnalyzedTarget, EventPublisher } from "../../core/entities/types";
import { logger } from "../../shared/systemLogger";
import { PHASES } from "../../shared/utils/const";
import { getErrorMessage } from "../../shared/utils/utils";
import { reconService } from "../phase1Recon/domain/phase1.repository";
import { streamAllSubdomains } from "../phase1Recon/domain/subdomain.useCase";
import { dnsPhaseStream } from "../phase2Dns/domain/infraResolver.useCase";
import { fingerprintingPhase } from "../phase3Surface/domain/serverFingerprinting.useCase";
import fingerprintingPhaseService from "../phase3Surface/domain/phase3.repository";

export class Orchestrator {
  constructor(private eventPublisher: EventPublisher){}
  private concurrencyLimit = 4;
  
  async start(target: string) {
    const activeWorkers = new Set<Promise<void>>();
    const allTasks: Promise<void>[] = [];
    const scannedIps = new Map<string, Promise<AnalyzedTarget>>();   
    let totalOfSubs=0;
    logger.info(PHASES.ORCHESTRATOR, "iniciando....");
    const scanId = reconService.startScan(target);
    const subdomainStream = streamAllSubdomains(target, scanId);
    
    for await (const sub of subdomainStream) {
      totalOfSubs++;
      if (activeWorkers.size >= this.concurrencyLimit) {
        await Promise.race(activeWorkers);
      }
      
      const worker = (async () => {
        try {
          // Fase 2: Resolución DNS, ASN y HTTP Intel base
          const result = await dnsPhaseStream(sub, scanId);
          if (!result || !result.ip || result.ip === "N/A" || result.ip === "0.0.0.0") return;


          this.eventPublisher.publish("host:discovered", "processing", {
            scanId,
            status:"process",
            target: result.host || "",
            ip: result.ip,
            open_ports:null,
            webserver:null,
            http_intel:null,
            total_stages_executed:2,
          });

          if (!scannedIps.has(result.ip)) {
            // CASO PADRE: Primera vez que vemos esta IP. Se ejecuta Nmap de forma real.
            const scanPromise = (async () => {
              return await fingerprintingPhase(result as AnalyzedTarget, scanId);
            })();

            scannedIps.set(result.ip, scanPromise);
            const finalData = await scanPromise;
            this.eventPublisher.publish("host:updated", "success", {
              scanId,
              status:"process",
              target:finalData.host,
              ip:finalData.ip,
              open_ports:finalData.open_ports,
              webserver:finalData.webserver,
              http_intel:finalData.http_intel,
              total_stages_executed:3,
            });
          } else {
            // CASO HIJO: Host único, pero la IP ya está siendo cubierta por un Padre.
            logger.debug(PHASES.ORCHESTRATOR, `Omitiendo Nmap para ${result.host}. IP ${result.ip} ya está cubierta.`);
            
            // Esperamos de forma asíncrona a que el Padre termine su fingerprinting
            const fatherData = await scannedIps.get(result.ip);
            
            if (fatherData) {
              // Inyectamos los puertos y la superficie descubierta por el Padre al contexto de este Hijo
              const updatedChild = {
                ...(result as AnalyzedTarget),
                open_ports: fatherData.open_ports || [],
                webserver: fatherData.webserver || result.webserver || null,
                http_intel: fatherData.http_intel,
                http_stack: fatherData.http_stack,
              };

              // Persistimos el registro del Hijo con sus puertos heredados en la base de datos
              fingerprintingPhaseService.saveFingerprintingInfo(result.host!, updatedChild, scanId);

              this.eventPublisher.publish("host:updated", "success", {
                scanId,
                status:"process",
                target: updatedChild.host,
                ip: updatedChild.ip,
                open_ports: updatedChild.open_ports,
                http_intel:updatedChild.http_intel,
                webserver: updatedChild.webserver,
                total_stages_executed:3,
              });
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

    this.eventPublisher.publish("phase-1", "completed", {
      scanId,
      status:"completed",
      total_subdomains_found:totalOfSubs,
      total_stages_executed:1,
    });
    await Promise.all(allTasks);

    this.eventPublisher.publish("scan:finished", "completed",
      { 
        scanId,
        status:"completed",
        total_stages_executed:3,
        total_subdomains_found:totalOfSubs,
      });
  }
}
