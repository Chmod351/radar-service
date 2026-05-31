import type { HttpIntel, WhoisIntel } from "../../core/entities/types";

export const PHASES={
  ORCHESTRATOR:"ORCHESTRATOR",
  RECON:"RECON",
}as const;

export const LOGGER={
  ERROR:0,
  WARN:1,
  INFO:2,
  DEBUG:3,
}as const;


export const SENSORS = {
  INFRA_TYPE: {
    UNKNOWN: 0,
    CLOUD: 1,
    SELF_HOSTED: 2,
  },
  ACTION: {
    SCAN_FAILED: 0,
    DUPLICATE: 1,
    SKIP: 2,
    READY: 3,
  },
} as const;

export const PROTOCOLS = {
  TRANSPORT:{
    TCP: 20,
    UDP:21,
    UNKNOWN:22,
  },
  APP:{
    UNKNOWN: 0,
    HTTP: 1,
    HTTPS: 2,
    SSH: 3,
    FTP: 4,
    DNS: 5,
    DATABASE: 6,
    MAIL: 7, // SMTP/IMAP
  },
} as const;

export const CDN_PROVIDERS = {
  NONE: 0,
  CLOUDFLARE: 1,
  AKAMAI: 2,
  CLOUDFRONT: 3,
  FASTLY: 4,
  INCAPSULA: 5,
  GOOGLE_CDN:6,
  GITHUB_CDN:7,
  AWS_S3:8,
  UNKNOWN_CDN: 99,
} as const;


export const emptyWhois: WhoisIntel = {
  registrar: null,
  creationDate: null,
  expirationDate: null,
  nameServers: [],
  status: [],
  emails: null,
  raw: "",
}; 
export const normalizedIntel: HttpIntel={
  protocol: PROTOCOLS.APP.UNKNOWN,
  status:0,
  security:{
    hsts:false,
    csp:false,
    xfo:false,
    nosniff:false,
  },server:null,
  poweredBy:null,
  cookies:false,
  error:null,
  attempts:[{
    method:"none",
    header:null,
    status:0,
    size:0,
    timestamp:"",
  }],
};
