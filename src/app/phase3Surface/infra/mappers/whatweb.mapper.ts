import type { Technology } from "../../../../core/entities/types";
import { logger } from "../../../../shared/systemLogger";
import { getErrorMessage } from "../../../../shared/utils/utils";
import type { WhatWebRawResponse } from "../../serverFingerPrintingProbe";

const  noise = [
  "IP", "HTTPServer", "Country", "Date", "BaseID",
  "Title", "HTML5", "Script", "X-UA-Compatible", "Email",
];


/* export function whatwebParser(rawContent:string) { */
/* if (!rawContent || rawContent.trim() === "" || !rawContent.includes("[")) return []; */
/*  */
/* const jsonStart = rawContent.indexOf("["); */
/* const jsonEnd = rawContent.lastIndexOf("]");  */
/* if (jsonStart === -1 || jsonEnd === -1 || jsonEnd < jsonStart) return [];  */
/* const cleanJson = rawContent.substring(jsonStart, jsonEnd + 1);  */
/*  */
/* const parsed = JSON.parse(cleanJson); */
/*  */
/* if (!Array.isArray(parsed) || parsed.length === 0) return [];  */
/* const lastResult=parsed[parsed.length -1]; */
/* const rawPlugins = (lastResult.plugins || {}) as WhatWebRawResponse; */
/* return parsePlugins(rawPlugins); */
/* } */
export function whatwebParser(rawContent: string) {
  if (!rawContent || !rawContent.includes("{")) return [];

  try {
    const jsonMatch = rawContent.match(/\[\s*\{.*\}\s*\]/s) || rawContent.match(/\{.*\}/s);
    if (!jsonMatch) {
      console.error("[WEBTECH] No se encontró estructura JSON válida en el output");
      return [];
    }
    const cleanJson = jsonMatch[0];
    const parsed = JSON.parse(cleanJson);
    const result = Array.isArray(parsed) ? parsed[parsed.length - 1] : parsed;
    
    if (!result || !result.plugins) return [];

    return parsePlugins(result.plugins);
  } catch (error) {
    logger.error("Whatweb:", getErrorMessage(error));
    return [];
  }
}


function parsePlugins(plugins:WhatWebRawResponse) {
  return Object.entries(plugins)
    .filter(([name]) => !noise.includes(name))
    .map(([name, details]): Technology => {
      const version = 
          details.version?.[0] || 
          details.string?.[0] || 
          details.module?.[0] || 
          "unknown";

      return {
        name,
        version,
      };
    })
    .filter(t => 
      t.version !== "unknown" || 
        ["Nginx", "Apache", "PHP", "WordPress", "Docker", "Cloudflare", "Laravel"].includes(t.name),
    );
}
