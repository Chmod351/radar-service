export function showManual() {
  console.log(`
 RADAR RECONNAISSANCE ENGINE (CLI v1.0.0)
 =======================================
 Uso: radar <operación> [argumento]

 OPERACIONES:
   -S <dominio>     Sincronizar y escanear un nuevo objetivo raíz.
                    Abstrae el entorno aislado en Docker.
                    Ejemplo: radar -S nmap.org
   -h, man, --help  Mostrar este manual de operaciones en la terminal.

  `);
}
