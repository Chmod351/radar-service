import type { ReconSource } from "../../../core/entities/types";

export const getReconSources=(target:string):ReconSource[]=> [
  { name: "Subfinder", cmd: "subfinder", args: ["-d", target, "-silent"] },
  { name: "Assetfinder", cmd: "assetfinder", args: ["--subs-only", target] },
];


