import { Database } from "bun:sqlite";
import tables from "./tables";
import type { AnalyzedTarget } from "../../core/entities/types";
import { logger } from "../../shared/systemLogger";
import { getErrorMessage } from "../../shared/utils/utils";
import { PATH } from "../enviromentVariables";

export class RadarRepository {
  private db: Database;

  constructor(dbPath: string = PATH) {
    this.db = new Database(dbPath);
    this.setup();
  }

  private setup() {
    this.db.run(tables);
    this.db.run("PRAGMA journal_mode = WAL;");

  }
  createScan(
    rootDomain:string,
  ):number | bigint{
    const sql= "INSERT OR IGNORE INTO scans (target_root) VALUES ($root)";
    return this.db.prepare(sql).run({ $root: rootDomain }).lastInsertRowid;
  }

  registerHost({ host,
    scanId,
    rootDomain }:{ host: string,
                   scanId: number|bigint,
                   rootDomain: string }) {
    const sql = "INSERT OR IGNORE INTO targets (host, scan_id, root_domain, scan_status) VALUES (?, ?, ?, 'DISCOVERED')";
    try {
    
      const res= this.db.prepare(sql).run(host, scanId, rootDomain);

      return res;
    } catch (e) {
    /* handle error */

      logger.error("REGISTERHOST", getErrorMessage(e));
      throw e;
    }
  }

  updateNetworkLayer(
    networkData:AnalyzedTarget,
    scanId:number|bigint,
  ){
    const infraSql = `
    INSERT INTO infrastructure (
      ip, asn, asn_owner
    ) VALUES (
      $ip, $asn, $asn_owner
    ) ON CONFLICT(ip) DO UPDATE SET  
      asn = COALESCE(excluded.asn, infrastructure.asn),
      last_updated = CURRENT_TIMESTAMP
    `;

    const targetSql = `
    UPDATE targets 
    SET ip = ?, url = ?,
      status_code = ?,
      title = ?,
      webserver = ?,
      cdn = ?,
      action = ?,
      scan_status = 'RESOLVED'
    WHERE host = ? AND scan_id = ?
    `;

    const { 
      ip, asn,  country, asn_owner, // Infra
      status_code, title, webserver, cdn, host,  url,action,        // Target
    } = networkData;

    try {
    // La transacción se define y se autoejecuta
      const tx = this.db.transaction(() => {
        this.db.prepare(infraSql).run({
          $ip: ip, 
          $asn: asn,
          $asn_owner: asn_owner,
          $country: country,
        });
        return this.db.prepare(targetSql).run(
          ip,
          url,
          status_code,
          title,
          webserver,
          cdn,
          action,
          host,
          scanId,
        );
      });
      tx();
     
      const target = this.db.prepare("SELECT id FROM targets WHERE host = ? AND scan_id = ?").get(host,scanId) as { id: number };
      if (!target) {
        throw new Error(`No se pudo encontrar el target recién actualizado: ${host}`);
      }
      return target.id;

    } catch (e) {
      /* handle error */
      logger.error("ERROR EN EL GUARDADO DE LA FASE 2", getErrorMessage(e));
      throw e;
    }
  }


  updateServiceLayer(host: string, data: AnalyzedTarget,scanId:number|bigint) {
    // 1. Query para actualizar los datos específicos del host escaneado por Nmap (Padre)
    const updateTargetSql = `
    UPDATE targets 
    SET status_code = $status,
    title = $title, 
    webserver = $server, 
    hsts = $hsts,     
    csp = $csp,        
    xfo = $xfo,       
    nosniff = $nosniff,
    app_status= $app_status,
    scan_status = 'COMPLETED'
    WHERE host = $host AND scan_id = $scanId
`;

    // 2. PROPAGACIÓN MASIVA: Iguala los datos de todos los targets que compartan la misma IP en este escaneo

    const propagateTargetsSql = `
      UPDATE targets
      SET status_code = $status,
          webserver = $server,
          hsts = $hsts,
          csp = $csp,
          xfo = $xfo,
          nosniff = $nosniff,
          app_status = $app_status,
          scan_status = 'COMPLETED'
      WHERE ip = (SELECT ip FROM targets WHERE host = $host AND scan_id = $scanId)
        AND scan_id = $scanId
    `;

    // 3. PROPAGACIÓN MASIVA DE PUERTOS: Limpia y clona los puertos para toda la vecindad de la IP
    const clearNeighborPortsSql = `
      DELETE FROM ports 
      WHERE target_id IN (
        SELECT id FROM targets WHERE ip = (SELECT ip FROM targets WHERE host = $host AND scan_id = $scanId) AND scan_id = $scanId
      )
    `;


    const insertNeighborPortsSql = `
      INSERT INTO ports (target_id, port, protocol, service, version)
      SELECT t.id, $port, $proto, $svc, $ver
      FROM targets t
      WHERE t.ip = (SELECT ip FROM targets WHERE host = $host AND scan_id = $scanId)
        AND t.scan_id = $scanId
    `;

    // 4. PROPAGACIÓN MASIVA DE HTTP STACK
    const clearNeighborStackSql = `
      DELETE FROM http_stack 
      WHERE target_id IN (
        SELECT id FROM targets WHERE ip = (SELECT ip FROM targets WHERE host = $host AND scan_id = $scanId) AND scan_id = $scanId
      )
    `;

    const insertNeighborStackSql = `
      INSERT INTO http_stack (target_id, name, version)
      SELECT t.id, $name, $version
      FROM targets t
      WHERE t.ip = (SELECT ip FROM targets WHERE host = $host AND scan_id = $scanId)
        AND t.scan_id = $scanId
    `;


    try {
      const transaction = this.db.transaction(() => {
      // Actualizar metadata del target
        const params = {
          $status: data.status_code,
          $title: data.title,
          $server: data.webserver,
          $hsts: data.http_intel.security.hsts ? 1 : 0,
          $csp: data.http_intel.security.csp ? 1 : 0,
          $xfo: data.http_intel.security.xfo ? 1 : 0,
          $nosniff: data.http_intel.security.nosniff ? 1 : 0,
          $app_status: data.app_status,
          $host: host,
          $scanId: scanId,
        };

        
        this.db.prepare(updateTargetSql).run(params);
        this.db.prepare(propagateTargetsSql).run(params);
        this.db.prepare(clearNeighborPortsSql).run({ $host: host, $scanId: scanId });
        
        const portStmt = this.db.prepare(insertNeighborPortsSql);
        for (const p of data.open_ports || []) {
          portStmt.run({
            $host: host,
            $scanId: scanId,
            $port: p.port,
            $proto: p.protocol || 6,
            $svc: p.service || "unknown",
            $ver: p.version || null,
          });
        }
      
        this.db.prepare(clearNeighborStackSql).run({ $host: host, $scanId: scanId }); 


        const stackStmt = this.db.prepare(insertNeighborStackSql);
        for (const tech of data.http_stack || []) {
          stackStmt.run({
            $host: host,
            $scanId: scanId,
            $name: tech.name,
            $version: tech.version || null,
          });
        }
      });

      return transaction();
   
    } catch (e) {
      /* handle error */
      logger.error("UPDATE SERVICE LAYER", getErrorMessage(e));
      throw e;
    }
  }



  syncRefinedData(refinedTargets: AnalyzedTarget[]) {
    const sql = `
    UPDATE targets 
    SET 
      app_status = $status,
      webserver = $webserver,
      action = $action,
      scan_status = 'COMPLETED'
    WHERE host = $host AND scan_id = $scanId
  `;
    try {
      const stmt = this.db.prepare(sql);
  
      const sync = this.db.transaction((targets) => {

        for (const t of targets) {
          stmt.run({
            $status: t.app_status,
            $webserver: t.webserver,
            $action: t.action,
            $host: t.host,
            $scanId: t.scanId,
          });
        }
      });

      sync(refinedTargets);
  

    } catch (e) {
    /* handle error */
      logger.error("SYNC FAILED", getErrorMessage(e));
      throw e;
    }
  }
}
 

export const repo= new RadarRepository();
