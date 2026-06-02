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

updateNetworkLayer(networkData: AnalyzedTarget, scanId: number | bigint) {
    const infraSql = `
      INSERT INTO infrastructure (
        scan_id, ip, asn, asn_owner, country, last_updated
      ) VALUES (
        $scan_id, $ip, $asn, $asn_owner, $country, CURRENT_TIMESTAMP
      ) ON CONFLICT(scan_id, ip) DO UPDATE SET  
        asn = COALESCE(excluded.asn, infrastructure.asn),
        asn_owner = COALESCE(excluded.asn_owner, infrastructure.asn_owner),
        country = COALESCE(excluded.country, infrastructure.country),
        last_updated = CURRENT_TIMESTAMP
    `;

    const targetSql = `
      UPDATE targets 
      SET ip = ?, 
          url = ?,
          status_code = ?,
          title = ?,
          webserver = ?,
          cdn = ?,
          action = ?,
          scan_status = 'RESOLVED'
      WHERE host = ? AND scan_id = ?
    `;

    const {
      ip, asn, country, asn_owner,
      status_code, title, webserver, cdn, host, url, action,
    } = networkData;

    try {
      const tx = this.db.transaction(() => {
        this.db.prepare(infraSql).run({
          $scan_id: Number(scanId),
          $ip: ip || "0.0.0.0",
          $asn: asn || null,
          $asn_owner: asn_owner || null,
          $country: country || null,
        });

        return this.db.prepare(targetSql).run(
          ip || "0.0.0.0",
          url || null,
          status_code || null,
          title || null,
          webserver || null,
          cdn || 0,
          action || 0,
          host,
          Number(scanId),
        );
      });
      
      tx();

      const target = this.db
        .prepare("SELECT id FROM targets WHERE host = ? AND scan_id = ?")
        .get(host, Number(scanId)) as { id: number } | undefined;

      if (!target) {
        throw new Error(`No se pudo encontrar el target recién actualizado: ${host}`);
      }
      return target.id;

    } catch (e) {
      logger.error("ERROR EN EL GUARDADO DE LA FASE 2", getErrorMessage(e));
      throw e;
    }
  }

updateServiceLayer(host: string, data: AnalyzedTarget, scanId: number | bigint) {
    const numericScanId = Number(scanId);

    const updateTargetSql = `
      UPDATE targets 
      SET status_code = $status,
          title = $title, 
          webserver = $server, 
          hsts = $hsts,      
          csp = $csp,        
          xfo = $xfo,       
          nosniff = $nosniff,
          app_status = $app_status,
          scan_status = 'COMPLETED'
      WHERE host = $host AND scan_id = $scanId
    `;

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

    const clearNeighborPortsSql = `
      DELETE FROM ports 
      WHERE target_id IN (
        SELECT id FROM targets WHERE ip = (SELECT ip FROM targets WHERE host = $host AND scan_id = $scanId) AND scan_id = $scanId
      )
    `;

    const insertNeighborPortsSql = `
      INSERT INTO ports (target_id, port, protocol, transport, service, version)
      SELECT t.id, $port, $proto, $transport, $svc, $ver
      FROM targets t
      WHERE t.ip = (SELECT ip FROM targets WHERE host = $host AND scan_id = $scanId)
        AND t.scan_id = $scanId
    `;

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
        const params = {
          $status: data.status_code || null,
          $title: data.title || null,
          $server: data.webserver || null,
          $hsts: data.http_intel?.security?.hsts ? 1 : 0,
          $csp: data.http_intel?.security?.csp ? 1 : 0,
          $xfo: data.http_intel?.security?.xfo ? 1 : 0,
          $nosniff: data.http_intel?.security?.nosniff ? 1 : 0,
          $app_status: data.app_status || 0,
          $host: host,
          $scanId: numericScanId,
        };

        this.db.prepare(updateTargetSql).run(params);
        this.db.prepare(propagateTargetsSql).run(params);
        
        this.db.prepare(clearNeighborPortsSql).run({ $host: host, $scanId: numericScanId });
        const portStmt = this.db.prepare(insertNeighborPortsSql);
        for (const p of data.open_ports || []) {
          portStmt.run({
            $host: host,
            $scanId: numericScanId,
            $port: p.port,
            $proto: p.protocol || "tcp", 
            $transport: (p as any).transport || 6, 
            $svc: p.service || "unknown",
            $ver: p.version || null,
          });
        }

        this.db.prepare(clearNeighborStackSql).run({ $host: host, $scanId: numericScanId }); 
        const stackStmt = this.db.prepare(insertNeighborStackSql);
        for (const tech of data.http_stack || []) {
          stackStmt.run({
            $host: host,
            $scanId: numericScanId,
            $name: tech.name,
            $version: tech.version || null,
          });
        }
      });

      return transaction();
    } catch (e) {
      logger.error("UPDATE SERVICE LAYER", getErrorMessage(e));
      throw e;
    }
  }

syncRefinedData(refinedTargets: (AnalyzedTarget & { scanId: number })[]) {
    const sql = `
      UPDATE targets 
      SET app_status = $status,
          webserver = $webserver,
          action = $action,
          scan_status = 'COMPLETED'
      WHERE host = $host AND scan_id = $scanId
    `;
    try {
      const stmt = this.db.prepare(sql);
      const sync = this.db.transaction((targets: any[]) => {
        for (const t of targets) {
          stmt.run({
            $status: t.app_status || 0,
            $webserver: t.webserver || null,
            $action: t.action || 0,
            $host: t.host,
            $scanId: Number(t.scanId),
          });
        }
      });
      sync(refinedTargets);
    } catch (e) {
      logger.error("SYNC FAILED", getErrorMessage(e));
      throw e;
    }
  }
}
 

export const repo= new RadarRepository();
