import { repo as dbRepo, type RadarRepository } from "../../../infra/db/repository";

export class ReconService {
  constructor(private repo: RadarRepository) {}

  async startScan(rootDomain: string):Promise<number | bigint> {
    return this.repo.createScan(rootDomain);
  }

  async processDiscovery(subdomain: string, scanId: number|bigint, rootDomain: string) {
    const result =this.repo.registerHost({
      host: subdomain,
      scanId: scanId,
      rootDomain: rootDomain,
    });

    return  result.changes > 0; 
     
  }
}

export const reconService= new ReconService(dbRepo);
