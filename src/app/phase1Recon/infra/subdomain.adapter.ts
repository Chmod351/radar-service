import { execa } from "execa";
import readline from "readline";
import { logger } from "../../../shared/systemLogger";

export async function* runSubdomainStream(cmd: string, args: string[]): AsyncIterable<string> {

  try {
    const childProcess = execa(cmd, args, {
      stdout: "pipe",
      stderr: "pipe",
    });

    const rl = readline.createInterface({
      input: childProcess.stdout!,
      terminal: false,
    });

    for await (const line of rl) {
      let cleanLine = line.trim().toLowerCase();
      yield cleanLine;
    }
    await childProcess; 
  } catch (e) {
    logger.error("BIN-STREAM", `Error en stream de ${cmd}:`, e);
    throw e;
  }
}

