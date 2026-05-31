import type { AnalyzedTarget, DnsPhase } from "../../../core/entities/types";
import { repo as dbRepo, type RadarRepository } from "../../../infra/db/repository";

export class InfraService {

  constructor(private repo: RadarRepository){}

  saveDNSphaseInfo(dnsPhase:DnsPhase,scanid:number|bigint){
    return this.repo.updateNetworkLayer(dnsPhase as AnalyzedTarget,scanid);
  }
}
const infraService= new InfraService(dbRepo);

export default infraService;
