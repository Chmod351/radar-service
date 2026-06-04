export interface Technology {
  name: string;
  version: string|null;
}

export interface BypassAttempt {
  method: string ;
  header: string | null;
  status: number;
  size: number;
  timestamp: string;
}

export interface WhatWebPluginDetails {
  version: string[]|null;
  string: string[]|null;
  module: string[]|null;
  os: string[]|null; 
}

export interface OpenPort {
  port: number;
  service: string |null;
  protocol: number
  version:string |null;
  transport:number;
}
export interface WhoisIntel {
  registrar: string |null;
  creationDate: string |null;
  expirationDate: string |null;
  nameServers: string[];
  status: string[];
  emails: string |null;
  raw: string; 
}

export interface SecurityHeaders {
  hsts: boolean;
  csp: boolean;
  xfo: boolean;
  nosniff: boolean;
}

export interface HttpIntel {
  protocol: number |null;
  status: number;
  security: SecurityHeaders;
  server: string |null;
  poweredBy: string |null;
  cookies: boolean;
  attempts:BypassAttempt[];
  error?: string | null;
}

export interface Fingerprint {
  server:string |null,
  version:string |null,
  product:string |null,
}

export interface ASNIntel {
  asn:string|null
   asn_owner: string |null;
   country:string|null
}

export interface ResolvedDomain {
  host: string;
  ip: string;
}
export interface WebMetadata {
  url: string;
  status_code: number;
  title: string|null;
  webserver: string |null;
  cdn: number | null;
}

export interface DnsPhase extends WebMetadata, ASNIntel,ResolvedDomain{}


export interface SearchSploitResult {
  Title: string;
  Path: string;
}

export interface SearchSploitOutput {
  Results: SearchSploitResult[] | []
}

export interface Classifier extends DnsPhase{
  action:number,
}

export interface AnalyzedTarget extends Classifier, ASNIntel , WebMetadata,ResolvedDomain{
  scanId:number|bigint;
  id:number|bigint;
  // Datos de Fase 3 
  http_intel: HttpIntel;
  http_stack: Technology[];
  open_ports:OpenPort[]

  // Datos de Fase 4
  vulnerabilities: SearchSploitResult[]
  app_status:number;

  whois: WhoisIntel;
  whois_raw: string | null
}


export interface ReconSource{
  name:string ; 
  cmd:string; 
  args:string[];
}

export interface EventPhaseEnd{
  scanId:number|bigint,
  id:number,
  status:"completed",
  total_stages_executed:number,
  total_subdomains_found:number
}

export interface EventSubdomainAnalisys{
  id:number|bigint,
  scanId:number|bigint,
  target:string,
  status:"process",
  ip:string,
  open_ports:OpenPort[]|null,
  http_intel:HttpIntel|null,
  webserver:string | null,
  total_stages_executed:number
}
// src/application/ports/EventPublisher.ts
export interface EventPublisher {
  publish(event: string, status: string, payload: EventPhaseEnd|EventSubdomainAnalisys): void;
}


