import { isDev, isTest } from "../infra/enviromentVariables";
import { LOGGER } from "./utils/const";

const colors=["\x1b[31m","\x1b[33m","\x1b[36m","\x1b[90m","\x1b[0m"];


class Logger {
  private isTest =  isTest;
  private isDev = isDev;

  private formatMessage(level:number, context: string, message: string): string {
    const ts = new Date().toLocaleString("es-AR", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
    const color = colors[level];
    const reset = "\x1b[0m";
    return `${color}[${ts}]  [${context}]${reset} ${message}`;
  }

  info(context: string, message: string) {
    if (!this.isTest && !this.isDev) console.log(this.formatMessage(LOGGER.INFO, context, message));
  }

  warn(context: string, message: string) {
    if (!this.isTest  && !this.isDev) console.warn(this.formatMessage(LOGGER.WARN, context, message));
  }

  error(context: string, message: string, error?: unknown) {
    // Los errores siempre se muestran, incluso en test si querés ver fallos críticos
    console.error(this.formatMessage(LOGGER.ERROR, context, message));
    if (error instanceof Error) {
      console.error(`\x1b[31m[STACK]\x1b[0m ${error.stack}`);
    }
  }

  debug(context: string, message: string) {
    if (this.isTest ||  this.isDev) {
      console.log(this.formatMessage(LOGGER.DEBUG, context, message));
    }
  }
}

export const logger = new Logger();
