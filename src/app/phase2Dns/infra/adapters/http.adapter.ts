import { execa } from "execa";
import { getErrorMessage } from "../../../../shared/utils/utils";
import { logger } from "../../../../shared/systemLogger";
// reemplazar esto por alguna lib

export async function getHttpHeaders(host: string): Promise<string> {

  try {
    const { stdout } = await execa("httpx-toolkit", [
      "-silent",
      "-json",
      "-title",
      "-web-server",
      "-status-code",
      "-no-color",
      // "-timeout", "4",
      // "-retries", "0",
    ], { input:host,
      timeout: 60000,
      // killSignal: "SIGTERM",
    });

    return stdout;

  } catch (e) {
  /* handle error */
    logger.error("FALLO HTTPX", getErrorMessage(e));
    return JSON.stringify({
      url: host,
      status_code: 0,
      failed: true,
      error: getErrorMessage(e),
    });
  }
}
