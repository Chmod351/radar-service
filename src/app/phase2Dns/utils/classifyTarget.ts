import type { AnalyzedTarget, DnsPhase } from "../../../core/entities/types";
import { SENSORS } from "../../../shared/utils/const";
import { cloudNoise } from "../../../shared/utils/data";


const globalFingerprints= new Set<string>();

export function classifyTarget(domainData: DnsPhase): Partial<AnalyzedTarget> {
  const asnOwner = (domainData.asn_owner || "").toLowerCase();
  const isNoise = cloudNoise.some(key => asnOwner.includes(key));

  const fingerprint = `${domainData.ip}_${domainData.status_code}_${domainData.title}`;


  let action:number = SENSORS.ACTION.SKIP;

  if (globalFingerprints.has(fingerprint)) {
    return { ...domainData, 
      action: SENSORS.ACTION.DUPLICATE ,
    };
  }

  globalFingerprints.add(fingerprint);
 
  if (isNoise) {
    return { ...domainData, 
      action, 
    };
  }
  action=SENSORS.ACTION.READY;

  return {
    ...domainData,
    action,
  };
}
