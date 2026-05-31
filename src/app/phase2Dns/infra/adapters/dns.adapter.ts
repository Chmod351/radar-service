import { execa } from "execa";
import { logger } from "../../../../shared/systemLogger";
import { getErrorMessage } from "../../../../shared/utils/utils";

export async function dnsResolver (domain:string):Promise<string> {

  try {
    const { stdout } =await execa("dnsx", [
      "-json",
      "-silent",
      "-nc",
      "-a",
      "-resp"],
    { input:domain,
      timeout: 10000 });

    return stdout;
    
  } catch (e:unknown) {
    /* handle error */
    logger.error("DNSX", getErrorMessage(e));
    throw e; 
  }
}
