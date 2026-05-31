#!/usr/bin/env bun
import { execSync } from "child_process";
import { showManual } from "./src/core/presentation/manual";
import { logger } from "./src/shared/systemLogger";
import { getErrorMessage } from "./src/shared/utils/utils";
import { isDev, isTest } from "./src/infra/enviromentVariables";

const args = process.argv.slice(2);
const flag = args[0];
const param = args[1];


async function main() {
  if (!flag || flag === "-h" || flag === "--help" || flag === "man") {
    showManual();
    process.exit(0);
  }

  switch (flag) {
  case "-S": // El flag de Escaneo que abstrae Docker
    if (!param) {
      console.error("❌ Error: Se requiere un dominio raíz. Ejemplo: radar -S nmap.org");
      process.exit(1);
    }
      
    runScanInDocker(param);
    break;

  default:
    console.log("❌ Flag desconocido. Escribí \"radar man\".");
    process.exit(1);
  }
}

function runScanInDocker(targetDomain: string) {
  const currentDir = process.cwd(); 
  
  const args = ["run", "--rm"];

  if (isDev || isTest) {
    args.push("-it");
    args.push("-v", `${currentDir}:/app`);
    args.push("--entrypoint", "bun");
  }

  const imageName = isDev || isTest ? "radar" : "Chmod351/radar:latest";
  args.push(imageName);

  // 3. Argumentos de ejecución del contenedor
  if (isDev || isTest) {
    args.push("run", "src/app/use-cases/index.ts", targetDomain);
  } else {
    args.push(targetDomain);
  }

  try {
    logger.info("DOCKER:", `Ejecutando escaneo para ${targetDomain}...`);
    
    execSync(`docker ${args.join(" ")}`, { stdio: "inherit" });
    
  } catch (error) {
    if (isDev || isTest) {
      logger.error("DOCKER_CRASH:", getErrorMessage(error));
    }
    console.error("\n❌ Error crítico en la ejecución del contenedor de Docker.");
    process.exit(1);
  }
}


main();
