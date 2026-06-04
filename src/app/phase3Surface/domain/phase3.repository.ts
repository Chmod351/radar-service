import type { AnalyzedTarget } from "../../../core/entities/types";
import { repo as dbRepo, type RadarRepository } from "../../../infra/db/repository";

export class FingerprintingPhaseService {
  constructor(private repo:RadarRepository){}

  async saveFingerprintingInfo(host:string,data:AnalyzedTarget,scanId:number|bigint){
    return this.repo.updateServiceLayer(host, data,scanId);  
  }
  async syncRefinedData(finalConsolidatedData:AnalyzedTarget[]){
    return this.repo.syncRefinedData(finalConsolidatedData); 
  }
}
const fingerprintingPhaseService=new FingerprintingPhaseService(dbRepo);
export default fingerprintingPhaseService;
