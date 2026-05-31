import { EventEmitter } from "node:events";
import type { EventPublisher } from "../../core/entities/types";
import { WEBHOOK_API } from "../../infra/enviromentVariables";
import { logger } from "../../shared/systemLogger";
import { getErrorMessage } from "../../shared/utils/utils";

export class BunEventPublisher implements  EventPublisher {
  private emitter: EventEmitter; 
  private webhook:string= WEBHOOK_API;

  constructor() {
    this.emitter = new EventEmitter();
    try {
      this.emitter.on("scan_event",async (eventData) => {
        console.log(JSON.stringify(eventData));
        await fetch(this.webhook,{
          method:"POST",
          headers:{
            "Content-Type": "application/json",
          },
          body:JSON.stringify(eventData),
        });
      });
    } catch (e) {
      /* handle error */
      logger.error("EVENT", getErrorMessage(e));
    }
  }

  public publish(event: string, status: string, payload: any): void {
    this.emitter.emit("scan_event", {
      timestamp: new Date().toISOString(),
      event,
      status,
      payload,
    });
  }
}

