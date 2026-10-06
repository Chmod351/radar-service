export const WEBHOOK_API:string = process.env.WEBHOOK_URL || "http://192.168.100.135:8080/api/webhook";
export const isDev:boolean      = process.env.NODE_ENV === "dev";
export const isTest: boolean    = process.env.NODE_ENV === "test";
export const isOsintMode = process.env.IS_OSINT ==="true";
export const scanId =Number(process.env.SCAN_ID);

export const PATH: string = process.env.RADAR_DB_PATH || ":memory:";
