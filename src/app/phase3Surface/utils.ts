import type { BypassAttempt } from "../../core/entities/types";
import { logger } from "../../shared/systemLogger";

export function compareSize(base: BypassAttempt, attempt: BypassAttempt, url: string) {
  if (base.size_complete === false || attempt.size_complete === false || attempt.status === 0) return;

  const delta = attempt.size - base.size;
  if (Math.abs(delta) > 50) {
    logger.warn("BYPASS", `Diferencia de tamaño observada (${delta} bytes) en ${attempt.header} contra ${url}`);
  }
}
