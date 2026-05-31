import { logger } from "../../shared/systemLogger";
import { PHASES } from "../../shared/utils/const";
import { TARGET } from "../../shared/utils/utils";
import { BunEventPublisher } from "../events/events.adapter";
import { Orchestrator } from "../orchestrator/orchestrator";
import { normalizeScanTarget } from "../orchestrator/url.mapper";

async function main(target:string) {
  const publisher= new BunEventPublisher();
  const orchestrator = new Orchestrator(publisher); 
  try {
    await orchestrator.start(target);
  } catch (error) {
    logger.error(PHASES.ORCHESTRATOR,`ERROR AL INTENTAR EJECUTAR EL ORQUESTADOR ${error}`);
    process.exit(1);
  }
}

if (TARGET) {
  main(normalizeScanTarget(TARGET));
}
