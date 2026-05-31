import { execa } from "execa";
import { existsSync } from "node:fs";
import { unlink,readFile } from "node:fs/promises";
import { logger } from "../../../../shared/systemLogger";
import { getErrorMessage } from "../../../../shared/utils/utils";



export async function getWebPageFingerprinting(target:string):Promise<string> {
  // whatweb suele meter ruido en el stdout asique lo guardamos en un archivo
  // temporal y de esa forma lo tenemos limpio
  const tempFile = `/tmp/whatweb_${Date.now()}_${Math.random().toString(36).slice(2)}.json`;

  try {
    await execa("whatweb", [
      "--color=never",
      "--no-errors",
      `--log-json=${tempFile}`,
      target,
    ], { reject: false, timeout: 25000 });

    if (!existsSync(tempFile)) return ""; 
    const rawContent =await readFile(tempFile, "utf-8");
      
    await unlink(tempFile); 

    return rawContent;
  } catch (e) {
  /* handle error */
    logger.error("WEB FINGERPRINTING", getErrorMessage(e));
    return "";
  }
  finally {

    try {
      if (existsSync(tempFile)) {
        await unlink(tempFile);
      }
    } catch (cleanupError) {
      // Si falla el borrado, solo lo logueamos, no rompemos el flujo principal
      logger.error("CLEANUP-TEMPFILE", getErrorMessage(cleanupError));
    }
  }
}
