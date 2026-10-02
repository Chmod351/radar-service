import type { EventPublisher } from "../../core/entities/types";
import { WEBHOOK_API } from "../../infra/enviromentVariables";
import { logger } from "../../shared/systemLogger";
import { getErrorMessage } from "../../shared/utils/utils";

export class BunEventPublisher implements EventPublisher {
  private webhook: string = WEBHOOK_API;
  private pendingRequests = new Set<Promise<void>>();

  constructor() {
    logger.info("EVENT", `Webhook configurado: ${this.webhook}`);
  }

  public publish(event: string, status: string, payload: any): Promise<void> {
    const eventData = {
      timestamp: new Date().toISOString(),
      event,
      status,
      payload,
    };
    const request = fetch(this.webhook, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(eventData),
    }).then((response) => {
      if (!response.ok) {
        throw new Error(`Webhook respondió ${response.status} ${response.statusText}`);
      }
      logger.info("EVENT", `Webhook aceptó ${event} (${response.status})`);
    });

    const trackedRequest = request.catch((error: unknown) => {
      logger.error("EVENT", `No se pudo enviar a ${this.webhook}: ${getErrorMessage(error)}`);
      throw error;
    }).finally(() => {
      this.pendingRequests.delete(trackedRequest);
    });

    this.pendingRequests.add(trackedRequest);
    return trackedRequest;
  }

  async flush(): Promise<void> {
    await Promise.allSettled(this.pendingRequests);
  }
}

