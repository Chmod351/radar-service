export const WEBHOOK_API:string = process.env.WEBHOOK_URL || "http://192.168.100.135:8080/api/webhook";
export const isDev:boolean      = process.env.NODE_ENV === "dev";
export const isTest: boolean    = process.env.NODE_ENV === "test";
const isDocker = process.env.IS_DOCKER === "true"; 
export const PATH: string = isDev || isTest 
  ? ":memory:" 
  : isDocker 
    ? "/app/data/radar.db"
    : "radar.db";
