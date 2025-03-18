
---

## 🔐 Mutual TLS (mTLS)

**1. ¿Qué es Mutual TLS (mTLS) y en qué se diferencia del TLS estándar?**  
*mTLS* es una extensión del protocolo TLS en la que tanto el cliente como el servidor se autentican mutuamente mediante certificados digitales.  
- **TLS estándar:** Solo el servidor presenta su certificado para que el cliente verifique su identidad.  
- **mTLS:** Además del certificado del servidor, el cliente también presenta el suyo, lo que aumenta la seguridad al asegurarse que ambos extremos son quienes dicen ser.

> **Ejemplo:**  
> En una API crítica, el servidor tiene un certificado emitido por una CA confiable y los clientes (por ejemplo, microservicios) tienen certificados propios. Al establecer la conexión, el servidor valida el certificado del cliente y viceversa.

---

**2. ¿Cómo funciona el proceso de autenticación en mTLS?**  
El proceso es similar al TLS pero con dos pasos de verificación:
- **Paso 1:** El cliente se conecta al servidor.  
- **Paso 2:** El servidor envía su certificado y solicita el certificado del cliente.  
- **Paso 3:** El cliente envía su certificado.  
- **Paso 4:** Ambas partes validan los certificados contra una lista de CA de confianza y comprueban revocaciones o caducidad.

> **Ejemplo:**  
> En un entorno Java con Spring Boot, al configurar el conector HTTPS se especifica el `trustStore` para validar el certificado del cliente y el `keyStore` para el propio certificado del servidor.

---

**3. ¿Qué ventajas aporta mTLS en términos de seguridad en comparación con otros métodos de autenticación?**  
- **Autenticación bidireccional:** Se asegura que ambas partes son confiables.  
- **Reducción de ataques man-in-the-middle:** Al validar ambos certificados, se dificulta la interceptación maliciosa.  
- **Integridad de la conexión:** Se cifra y asegura la comunicación en ambos extremos.

> **Ejemplo:**  
> En una arquitectura de microservicios, mTLS previene que un servicio no autorizado pueda interactuar con otros, ya que cada servicio debe presentar un certificado válido.

---

**4. ¿Cuáles son los pasos para configurar mTLS en un servidor Nginx o Apache?**  
1. **Generar certificados:** Crear certificados para el servidor y cada cliente.  
2. **Configurar el servidor web:**  
   - En **Nginx**, se configuran las directivas `ssl_certificate`, `ssl_certificate_key` y `ssl_client_certificate` junto con `ssl_verify_client on;` para requerir la validación del cliente.  
   - En **Apache**, se usan directivas como `SSLCertificateFile`, `SSLCertificateKeyFile`, `SSLCACertificateFile` y `SSLVerifyClient require`.

> **Ejemplo en Nginx:**  
> ```nginx
> server {
>     listen 443 ssl;
>     ssl_certificate /etc/nginx/ssl/server.crt;
>     ssl_certificate_key /etc/nginx/ssl/server.key;
>     ssl_client_certificate /etc/nginx/ssl/ca.crt;
>     ssl_verify_client on;
>     ...
> }
> ```

---

**5. ¿Cómo generar y gestionar certificados de cliente y servidor en mTLS?**  
- **Generación:** Se pueden usar herramientas como OpenSSL para generar claves y certificados.
- **Gestión:**  
  - **Servidor:** Almacena su certificado en un keystore (por ejemplo, PKCS12) y la lista de CA en un truststore.  
  - **Cliente:** Similarmente, gestiona su propio keystore y confía en el truststore del servidor.  
- **Renovación y revocación:** Se debe tener un proceso automatizado para renovar certificados antes de su expiración y un mecanismo (como CRL o OCSP) para revocar certificados comprometidos.

> **Ejemplo usando OpenSSL:**  
> ```bash
> # Generar clave privada del servidor
> openssl genrsa -out server.key 2048
>
> # Crear una solicitud de firma de certificado (CSR)
> openssl req -new -key server.key -out server.csr
>
> # Firmar el certificado con una CA
> openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365
> ```

---

**6. ¿Cuál es la diferencia entre un certificado auto-firmado y uno emitido por una CA confiable en el contexto de mTLS?**  
- **Certificado auto-firmado:** El emisor y el receptor son el mismo; útil en entornos de desarrollo o pruebas.  
- **Certificado emitido por una CA confiable:** Es firmado por una entidad de confianza, lo que facilita la validación y es más seguro en entornos productivos.

> **Ejemplo:**  
> En producción, se utiliza un certificado emitido por una CA reconocida (como DigiCert o Let's Encrypt) para evitar que clientes rechacen la conexión por no confiar en un certificado auto-firmado.

---

**7. ¿Cómo se maneja la revocación de certificados en mTLS? ¿Qué mecanismos existen?**  
- **CRL (Certificate Revocation List):** Lista de certificados revocados publicada por la CA.  
- **OCSP (Online Certificate Status Protocol):** Permite verificar el estado de un certificado en tiempo real.

> **Ejemplo:**  
> Un servidor puede configurar su software para consultar OCSP y así verificar que el certificado presentado por el cliente no ha sido revocado antes de establecer la conexión.

---

**8. ¿Cómo implementas mTLS en un microservicio con Spring Boot?**  
1. **Generar y configurar certificados:** Preparar keystore y truststore.  
2. **Configurar application.properties (o application.yml):**  
   ```properties
   server.port=8443
   server.ssl.key-store=classpath:server.p12
   server.ssl.key-store-password=changeit
   server.ssl.key-store-type=PKCS12
   server.ssl.trust-store=classpath:truststore.p12
   server.ssl.trust-store-password=changeit
   server.ssl.client-auth=need
   ```
3. **Verificar la autenticación:** Usar filtros o interceptores si se requiere lógica adicional.

> **Ejemplo:**  
> Al iniciar la aplicación, Spring Boot forzará la presentación de un certificado por parte del cliente y rechazará conexiones sin él.

---

**9. ¿Cómo solucionarías problemas de compatibilidad con mTLS en un entorno de múltiples clientes con diferentes certificados?**  
- **Actualizar la lista de CA de confianza:** Asegurarse de que el truststore contenga todas las CA emisoras de los certificados de los clientes.  
- **Política de validación flexible:** Configurar validaciones que permitan diferentes formatos o versiones de certificados.  
- **Monitoreo y logging:** Habilitar logs detallados para identificar errores de validación y ajustar configuraciones.

> **Ejemplo:**  
> Si algunos clientes usan certificados de una CA interna y otros de una externa, se debe incluir ambas CA en el truststore del servidor y, en algunos casos, personalizar la lógica de validación para aceptar atributos específicos.

---

**10. ¿Cuáles son las desventajas o limitaciones de mTLS en comparación con OAuth2 o JWT?**  
- **Complejidad operativa:** La gestión y renovación de certificados puede ser más compleja.  
- **Escalabilidad:** En entornos con miles de clientes, mantener y distribuir certificados de forma segura es un desafío.  
- **Flexibilidad:** OAuth2 y JWT ofrecen mecanismos más dinámicos para delegar permisos y escalar autenticación en entornos distribuidos.

> **Ejemplo:**  
> Mientras que mTLS requiere la configuración de certificados en cada cliente, OAuth2 permite delegar la autenticación a un servidor de autorización, simplificando el manejo en aplicaciones web o móviles.

---

## 🔒 Ciberseguridad

**11. ¿Cuáles son los principios fundamentales de la ciberseguridad? (CIA Triad)**  
- **Confidencialidad:** Asegurar que la información solo sea accesible para usuarios autorizados.  
- **Integridad:** Garantizar que la información no sea alterada de manera no autorizada.  
- **Disponibilidad:** Asegurar que la información y servicios estén disponibles cuando se necesiten.

> **Ejemplo:**  
> En una API bancaria, la confidencialidad se asegura cifrando datos sensibles, la integridad se verifica mediante firmas digitales y la disponibilidad se garantiza con arquitecturas redundantes y balanceo de carga.

---

**12. ¿Cómo se puede proteger una API REST contra ataques de fuerza bruta?**  
- **Implementar rate limiting:** Limitar el número de peticiones por IP o token.  
- **Bloqueo temporal:** Suspender la IP tras múltiples intentos fallidos.  
- **Captcha:** Requerir verificación adicional en solicitudes sospechosas.

> **Ejemplo:**  
> Usar herramientas como Nginx o API Gateways (Kong, Apigee) para limitar a 100 peticiones por minuto por IP, evitando ataques automatizados.

---

**13. ¿Qué estrategias implementas para mitigar ataques DDoS en una API pública?**  
- **Uso de WAF (Web Application Firewall):** Detectar y bloquear patrones de ataque.  
- **Escalado automático y CDN:** Distribuir la carga y mitigar el tráfico malicioso.  
- **Rate limiting y circuit breakers:** Controlar la saturación de peticiones.

> **Ejemplo:**  
> Configurar AWS Shield junto con un balanceador de carga para filtrar el tráfico y evitar que un ataque DDoS derribe la API.

---

**14. ¿Cómo manejarías una fuga de credenciales en un repositorio Git?**  
- **Revocar las credenciales inmediatamente:** Cambiar contraseñas, tokens o claves expuestas.  
- **Reescribir el historial:** Usar herramientas como `git filter-branch` o `BFG Repo-Cleaner` para eliminar la información sensible.  
- **Auditar y monitorizar:** Implementar políticas para evitar que se suba información sensible en el futuro.

> **Ejemplo:**  
> Si se descubre un archivo con una API key, se revoca la key, se elimina el archivo del historial y se configura un pre-commit hook para evitar futuros errores.

---

**15. ¿Cómo te aseguras de que el código de una aplicación web está protegido contra inyección SQL y XSS?**  
- **Validación y sanitización de entradas:** Usar frameworks y bibliotecas que escapen caracteres peligrosos.  
- **Consultas parametrizadas:** Emplear ORM o consultas preparadas para prevenir inyección SQL.  
- **Política de CSP y validación en el lado del servidor:** Para prevenir XSS.

> **Ejemplo:**  
> En Java, al usar JDBC se recomienda usar `PreparedStatement` en lugar de concatenar cadenas en las consultas SQL.

---

**16. ¿Qué es CORS y cómo afecta a la seguridad de una aplicación web?**  
- **CORS (Cross-Origin Resource Sharing):** Es un mecanismo que permite o restringe recursos solicitados desde un dominio distinto al que sirve la aplicación.  
- **Impacto en seguridad:** Configuraciones laxas pueden permitir que sitios maliciosos consuman APIs sin autorización.

> **Ejemplo:**  
> Configurar CORS en un backend Spring Boot:
> ```java
> @CrossOrigin(origins = "https://dominio-seguro.com")
> @RestController
> public class MiControlador { ... }
> ```

---

**17. ¿Qué es HSTS (HTTP Strict Transport Security) y por qué es importante?**  
- **HSTS:** Es una política de seguridad que indica a los navegadores que sólo deben comunicarse a través de HTTPS, evitando conexiones inseguras.  
- **Importancia:** Previene ataques de downgrade y fuerza a usar siempre conexiones cifradas.

> **Ejemplo:**  
> En Nginx se puede habilitar:
> ```nginx
> add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
> ```

---

**18. Explica cómo funciona el seguro de contenido CSP (Content Security Policy) en las aplicaciones web.**  
- **CSP:** Es un mecanismo de seguridad que ayuda a detectar y mitigar ciertos tipos de ataques, como XSS y data injection, al restringir las fuentes de contenido que el navegador puede cargar.  
- **Funcionamiento:** Se define una política (a través de cabeceras HTTP) que especifica de dónde se pueden cargar scripts, estilos, imágenes, etc.

> **Ejemplo:**  
> Una política CSP básica:
> ```http
> Content-Security-Policy: default-src 'self'; script-src 'self' https://apis.seguras.com;
> ```

---

**19. ¿Qué son los Zero Trust Networks (ZTN) y cómo mejorarían la seguridad en una arquitectura basada en microservicios?**  
- **Zero Trust:** Modelo de seguridad en el que no se asume la confiabilidad de ningún elemento, incluso dentro de la red corporativa.  
- **Beneficios:**  
> - Autenticación y autorización continua entre servicios.  
> - Segmentación de red estricta y políticas basadas en identidades.

> **Ejemplo:**  
> En microservicios, se puede aplicar Zero Trust integrando autenticación mTLS, OAuth2 y controles de acceso a nivel de API Gateway para verificar cada petición, sin asumir confianza por pertenecer a la red interna.

---

**20. ¿Cómo asegurarías los secretos en una aplicación (API keys, passwords, certificados)?**  
- **Almacenamiento seguro:** Uso de gestores de secretos como HashiCorp Vault, AWS Secrets Manager o Azure Key Vault.  
- **Encriptación y acceso restringido:** Cifrado de secretos y otorgar accesos mínimos necesarios.  
- **Rotación periódica:** Implementar políticas de rotación y revocación.

> **Ejemplo:**  
> Configurar Spring Cloud Vault para cargar secretos desde Vault en tiempo de ejecución en lugar de almacenarlos en archivos de configuración.

---

## 🏷️ JSON Web Token (JWT)

**21. ¿Qué es un JSON Web Token (JWT) y cómo funciona?**  
- **JWT:** Es un estándar abierto (RFC 7519) para transmitir información de forma segura entre partes como un objeto JSON firmado.  
- **Funcionamiento:** Un JWT se compone de tres partes (header, payload y signature) que se codifican en Base64. El receptor verifica la firma para asegurar que los datos no han sido alterados.

> **Ejemplo:**  
> Un JWT podría tener un header:
> ```json
> { "alg": "HS256", "typ": "JWT" }
> ```
> y un payload:
> ```json
> { "sub": "1234567890", "name": "Rami", "iat": 1516239022 }
> ```

---

**22. ¿Cuáles son las principales partes de un JWT y qué información contiene cada una?**  
- **Header:** Contiene el algoritmo de firma y el tipo de token.  
- **Payload:** Contiene los claims o afirmaciones (por ejemplo, datos del usuario, roles, expiración).  
- **Signature:** Es el resultado de firmar el header y payload con una clave secreta o par de claves.

> **Ejemplo:**  
> Un JWT codificado puede verse así:  
> `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlJhbWkiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`

---

**23. ¿Qué significa que JWT es un token self-contained?**  
- **Self-contained:** Toda la información necesaria para la autenticación y autorización se encuentra dentro del token, sin necesidad de consultar una base de datos adicional en cada petición (aunque se puede invalidar de otras maneras).

> **Ejemplo:**  
> El token contiene el ID de usuario, roles y expiración, lo que permite al servicio validar la sesión sin buscar en un almacén centralizado.

---

**24. ¿Cómo evitarías que un atacante use un JWT robado en una sesión activa?**  
- **Implementar expiraciones cortas:** Reducir la ventana en la que un token es válido.  
- **Uso de refresh tokens:** Renovar el acceso con tokens de corta duración.  
- **Incluir claims de contexto:** Como la IP o el User-Agent, y validar que coincidan en cada petición.  
- **Revocación centralizada:** Mantener una lista negra en casos críticos.

> **Ejemplo:**  
> Al detectar actividad sospechosa, se invalida el refresh token y se fuerza al usuario a autenticarse nuevamente.

---

**25. ¿Cuáles son los algoritmos de firma más utilizados en JWT? Explica HS256, RS256 y ES256.**  
- **HS256:** Algoritmo simétrico que utiliza una clave secreta compartida para firmar y verificar el token.  
- **RS256:** Algoritmo asimétrico basado en RSA; utiliza una clave privada para firmar y una clave pública para verificar.  
- **ES256:** Basado en curvas elípticas, es asimétrico y ofrece una firma más corta y, en muchos casos, mayor seguridad.

> **Ejemplo:**  
> En una implementación con HS256, tanto el emisor como el receptor deben conocer la misma clave secreta. Con RS256, el emisor firma con su clave privada y el receptor usa la clave pública para la verificación.

---

**26. ¿Cómo implementarías JWT con expiración corta y refresh tokens de manera segura?**  
- **Expiración corta:** Configurar el token de acceso para que tenga una validez breve (por ejemplo, 15 minutos).  
- **Refresh tokens:** Emitir un token de larga duración que permita obtener nuevos tokens de acceso sin reautenticarse, almacenándolo de forma segura.  
- **Rotación de refresh tokens:** Invalida el refresh token después de su uso y emite uno nuevo.

> **Ejemplo en Spring Boot:**  
> Un endpoint `/login` genera un JWT con `exp=15 minutos` y un refresh token. El endpoint `/refresh` valida el refresh token, emite un nuevo JWT y rota el refresh token.

---

**27. ¿Qué ventajas y desventajas tiene JWT frente a sesiones basadas en cookies?**  
- **Ventajas:**  
  - Stateless, lo que permite escalabilidad horizontal sin almacenamiento de sesión en el servidor.  
  - Autocontenidos: la información se almacena en el token.  
- **Desventajas:**  
  - Revocación compleja: una vez emitido, el token es válido hasta su expiración.  
  - Tamaño del token puede ser mayor y expone más datos (aunque codificados).

> **Ejemplo:**  
> En sistemas distribuidos, JWT es ideal por su naturaleza sin estado, pero para aplicaciones donde se requiere revocar accesos inmediatamente, las sesiones tradicionales pueden ser más sencillas de manejar.

---

**28. ¿Cómo verificarías la validez de un JWT en una aplicación Spring Boot?**  
- **Filtros de seguridad:** Usar un filtro (por ejemplo, en Spring Security) que intercepte las peticiones y verifique la firma, la fecha de expiración y otros claims.  
- **Bibliotecas:** Utilizar bibliotecas como `jjwt` o `nimbus-jose-jwt`.

> **Ejemplo:**  
> ```java
> String token = request.getHeader("Authorization").substring(7);
> Claims claims = Jwts.parser()
>     .setSigningKey(secretKey)
>     .parseClaimsJws(token)
>     .getBody();
> // Validar expiración y otros claims...
> ```

---

**29. ¿Cómo invalidar un JWT antes de su expiración sin un backend centralizado?**  
- **Lista negra:** Mantener en caché una lista de tokens revocados (aunque se requiere cierto estado).  
- **Uso de versiones o identificadores:** Incluir un claim (por ejemplo, `tokenVersion`) y, en el backend, comparar con la versión almacenada para el usuario.  
- **Cambio de clave secreta:** En casos extremos, rotar la clave de firma, invalidando todos los tokens.

> **Ejemplo:**  
> Una estrategia es almacenar en una base de datos el último `tokenVersion` de cada usuario y comparar el claim en el JWT; si no coincide, se rechaza el token.

---

**30. ¿Cómo evitar ataques JWT None Algorithm?**  
- **Validación estricta del algoritmo:** Configurar la biblioteca de JWT para rechazar tokens cuyo header especifique `alg: none`.  
- **Uso de bibliotecas actualizadas:** Asegurarse de usar implementaciones que no permitan omitir la firma.

> **Ejemplo:**  
> En `jjwt`, se configura el parser para que solo acepte algoritmos específicos:
> ```java
> Jwts.parser().setAllowedClockSkewSeconds(30).setSigningKey(secretKey)
>     .parseClaimsJws(token);
> ```
> Esto previene que un token con `alg: none` pase la validación.

---

## 🔄 Git y Control de Versiones

**31. Explica la diferencia entre Git Merge y Git Rebase.**  
- **Merge:** Combina ramas creando un commit de fusión que preserva la historia completa.  
- **Rebase:** Reescribe la historia moviendo los commits a la punta de otra rama, produciendo un historial lineal.

> **Ejemplo:**  
> Supongamos que tienes la rama `feature` y deseas integrarla a `master`:
> - Con **merge:** `git checkout master && git merge feature` crea un commit de merge.  
> - Con **rebase:** `git checkout feature && git rebase master` y luego `git checkout master && git merge feature` (fast-forward).

---

**32. ¿Qué son los commit hashes en Git y cómo funcionan?**  
- Cada commit en Git tiene un identificador único (hash SHA-1 o SHA-256 en versiones nuevas) que permite identificar de forma única un snapshot del repositorio.  
- Se utilizan para referenciar commits en operaciones como revert, cherry-pick o comparación.

> **Ejemplo:**  
> Un commit puede tener un hash como `a1b2c3d4...` y se puede usar para revertir: `git revert a1b2c3d4`.

---

**33. ¿Cuál es la diferencia entre un rebase interactivo y un merge?**  
- **Rebase interactivo:** Permite editar, reordenar o combinar commits de forma interactiva antes de aplicarlos sobre otra rama, ideal para limpiar el historial.  
- **Merge:** Combina ramas sin reescribir el historial, preservando la trazabilidad de los commits.

> **Ejemplo:**  
> `git rebase -i master` te permite modificar los commits de tu rama actual antes de integrarla a `master`.

---

**34. ¿Cómo revertir un commit sin perder cambios en el código?**  
- **Uso de `git revert`:** Crea un nuevo commit que invierte los cambios del commit especificado sin modificar el historial.

> **Ejemplo:**  
> `git revert a1b2c3d4` crea un commit que deshace los cambios introducidos por ese hash.

---

**35. ¿Qué es Git Squash y en qué escenarios lo usarías?**  
- **Git Squash:** Es la técnica de combinar varios commits en uno solo.  
- **Escenarios:** Ideal para limpiar el historial antes de hacer merge a la rama principal, consolidando commits menores o de corrección.

> **Ejemplo:**  
> Durante un rebase interactivo (`git rebase -i`), se puede cambiar `pick` por `squash` en los commits que se desean combinar.

---

**36. ¿Cómo manejarías conflictos de fusión en Git de manera efectiva?**  
- **Resolución manual:** Revisar el conflicto en el archivo y seleccionar o combinar las partes correctas.  
- **Herramientas de merge:** Utilizar herramientas gráficas o integradas en IDEs para comparar versiones.  
- **Comunicación:** Asegurar que el equipo esté informado de las áreas conflictivas y trabajar en ramas feature separadas.

> **Ejemplo:**  
> Al hacer un merge y aparecer un conflicto, se pueden usar herramientas como `meld` o la integración de VS Code para resolver diferencias.

---

**37. Explica el flujo de trabajo de Gitflow y cuándo aplicarlo.**  
- **Gitflow:** Es un modelo de ramificación que define ramas principales: `master` para producción, `develop` para integración y ramas de `feature`, `release` y `hotfix` para organizar el desarrollo.  
- **Aplicación:** Útil en proyectos con ciclos de release definidos y equipos grandes para mantener un historial claro.

> **Ejemplo:**  
> Se crea una rama de feature a partir de `develop`, una vez terminada se mergea de vuelta a `develop`. Cuando se acerca un release, se crea una rama `release` para ajustes finales y, posteriormente, se fusiona en `master` y `develop`.

---

**38. ¿Qué es un submódulo de Git y en qué casos lo usarías?**  
- **Submódulo:** Permite incluir un repositorio Git dentro de otro, manteniendo sus historiales separados.  
- **Casos de uso:** Integrar dependencias o librerías internas que evolucionan de forma independiente.

> **Ejemplo:**  
> Para incluir una librería interna:
> ```bash
> git submodule add https://github.com/tuorg/mi-libreria.git libs/mi-libreria
> ```

---

**39. ¿Cómo clonar un repositorio sin historial de commits para reducir tamaño?**  
- Se puede usar la opción `--depth 1` para obtener un *clone shallow* sin el historial completo.

> **Ejemplo:**  
> `git clone --depth 1 https://github.com/usuario/repositorio.git`

---

**40. ¿Cómo recuperar un branch eliminado en Git si no fue pushado al remoto?**  
- Si el branch se eliminó localmente, se puede buscar en el reflog y recrear la rama desde el commit correspondiente.

> **Ejemplo:**  
> ```bash
> git reflog
> # Encuentra el hash del commit
> git checkout -b branch_recuperado <hash>
> ```

---

## ⚙️ Maven

**41. ¿Cuáles son las fases principales del ciclo de vida de Maven?**  
- **Validate:** Verifica que el proyecto esté correcto y toda la información necesaria esté presente.  
- **Compile:** Compila el código fuente del proyecto.  
- **Test:** Ejecuta pruebas unitarias.  
- **Package:** Empaqueta el proyecto en su formato distribuible (jar, war, etc.).  
- **Verify:** Realiza comprobaciones adicionales en el paquete.  
- **Install:** Instala el paquete en el repositorio local.  
- **Deploy:** Copia el paquete al repositorio remoto para compartirlo con otros.

> **Ejemplo:**  
> Al ejecutar `mvn clean install`, se recorren estas fases hasta instalar el artefacto localmente.

---

**42. ¿Cómo configuras y utilizas diferentes perfiles en Maven para distintos entornos?**  
- **Perfiles:** Permiten definir configuraciones específicas (por ejemplo, dependencias, propiedades, plugins) para entornos como dev, test o prod.
- **Configuración:** Se define en el `pom.xml` o en el archivo `settings.xml` y se activa mediante la opción `-P`.

> **Ejemplo en `pom.xml`:**  
> ```xml
> <profiles>
>   <profile>
>     <id>dev</id>
>     <properties>
>       <env>development</env>
>     </properties>
>   </profile>
>   <profile>
>     <id>prod</id>
>     <properties>
>       <env>production</env>
>     </properties>
>   </profile>
> </profiles>
> ```
> Para activar: `mvn clean package -Pprod`

---

**43. ¿Para qué sirven los plugins en Maven y cuáles son los más comunes?**  
- **Plugins:** Extienden la funcionalidad de Maven para tareas como compilación, testing, empaquetado y despliegue.  
- **Plugins comunes:**  
> - `maven-compiler-plugin`: Compilación de código.  
> - `maven-surefire-plugin`: Ejecución de pruebas unitarias.  
> - `maven-failsafe-plugin`: Pruebas de integración.  
> - `maven-jar-plugin`: Empaquetado en formato JAR.

---

**44. ¿Cómo manejarías dependencias con diferentes alcances en Maven?**  
- **Alcances (scopes):**  
> - `compile`: Disponible en todas las fases.  
> - `provided`: Se espera que el entorno de ejecución provea la dependencia (por ejemplo, un servlet container).  
> - `runtime`: Necesario sólo en tiempo de ejecución.  
> - `test`: Solo para pruebas.
- Se especifican en el `<dependency>` correspondiente en el `pom.xml`.

> **Ejemplo:**  
> ```xml
> <dependency>
>   <groupId>javax.servlet</groupId>
>   <artifactId>servlet-api</artifactId>
>   <version>2.5</version>
>   <scope>provided</scope>
> </dependency>
> ```

---

**45. ¿Qué ocurre en Maven cuando agregas una dependencia con conflictos?**  
- **Conflictos de versiones:** Maven usa el mecanismo de "nearest definition" para resolver conflictos, tomando la versión más cercana en la jerarquía de dependencias.
- **Solución:** Se puede utilizar la sección `<dependencyManagement>` para forzar una versión específica.

> **Ejemplo:**  
> Si dos librerías requieren diferentes versiones de `commons-logging`, se puede declarar en `<dependencyManagement>` la versión deseada.

---

**46. ¿Cómo ejecutar pruebas unitarias e integración separadamente con Maven?**  
- **Surefire Plugin:** Ejecuta pruebas unitarias durante la fase `test`.  
- **Failsafe Plugin:** Ejecuta pruebas de integración en la fase `integration-test` o `verify`.
  
> **Ejemplo:**  
> Configurar en el `pom.xml` y luego ejecutar:
> ```bash
> mvn test          # Ejecuta pruebas unitarias
> mvn verify        # Ejecuta pruebas de integración con failsafe
> ```

---

**47. ¿Qué diferencia hay entre un parent POM y un BOM en Maven?**  
- **Parent POM:** Sirve para centralizar la configuración y heredar propiedades, plugins y dependencias en múltiples módulos.  
- **BOM (Bill Of Materials):** Permite gestionar versiones de un conjunto de dependencias para que sean consistentes en un proyecto.

> **Ejemplo:**  
> Un proyecto puede tener un parent POM que defina la versión de Spring, y un BOM para unificar versiones de librerías de Apache, asegurando que todas usen la misma versión.

---

**48. ¿Qué es el Assembly plugin y cuándo usarlo?**  
- **Assembly Plugin:** Se utiliza para crear paquetes distribuidos (por ejemplo, zips, tarballs) que contengan el binario y recursos adicionales.
- **Uso:** Cuando se requiere empaquetar el proyecto junto con scripts, configuraciones y dependencias externas.

> **Ejemplo:**  
> Configurar el `maven-assembly-plugin` para crear un archivo ZIP que incluya el JAR generado y un script de inicio.

---

## 🏛️ Patrones de Diseño

**49. Explica en qué consisten los principios SOLID.**  
- **S:** Single Responsibility Principle – Una clase debe tener una única responsabilidad.  
- **O:** Open/Closed Principle – Las clases deben estar abiertas a la extensión, pero cerradas a la modificación.  
- **L:** Liskov Substitution Principle – Las subclases deben ser sustituibles por sus clases base.  
- **I:** Interface Segregation Principle – Se deben crear interfaces específicas y no forzar a implementar métodos innecesarios.  
- **D:** Dependency Inversion Principle – Los módulos de alto nivel no deben depender de módulos de bajo nivel, sino de abstracciones.

> **Ejemplo:**  
> En una aplicación, separar la lógica de negocio de la de persistencia permite modificar una sin afectar la otra, cumpliendo el SRP y el DIP.

---

**50. ¿Qué diferencias hay entre los patrones Creacionales, Estructurales y de Comportamiento?**  
- **Creacionales:** Se centran en la instanciación de objetos (por ejemplo, Singleton, Factory).  
- **Estructurales:** Organizan clases y objetos en grandes estructuras (por ejemplo, Adapter, Facade, Decorator).  
- **De Comportamiento:** Definen la comunicación entre objetos (por ejemplo, Observer, Strategy, Command).

> **Ejemplo:**  
> Utilizar un **Factory Method** para crear instancias de diferentes implementaciones de una interfaz (creacional) o aplicar un **Decorator** para agregar funcionalidades a un objeto sin modificar su estructura (estructural).

---

**51. ¿Cómo implementarías un Singleton de manera segura en entornos concurrentes?**  
- **Implementación thread-safe:**  
> - Uso de `synchronized` en el método de obtención de la instancia.  
> - Uso de *double-checked locking* o la inicialización estática.

> **Ejemplo en Java:**  
> ```java
> public class Singleton {
>     private static volatile Singleton instance;
>     
>     private Singleton() { }
>     
>     public static Singleton getInstance() {
>         if (instance == null) {
>             synchronized(Singleton.class) {
>                 if (instance == null) {
>                     instance = new Singleton();
>                 }
>             }
>         }
>         return instance;
>     }
> }
> ```

---

**52. ¿En qué casos usarías el patrón Factory Method vs. Abstract Factory?**  
- **Factory Method:** Cuando se necesita delegar la creación de un objeto a subclases, útil para crear una sola familia de productos.  
- **Abstract Factory:** Cuando se requiere crear familias de objetos relacionados sin especificar sus clases concretas.

> **Ejemplo:**  
> - **Factory Method:** Una clase base `Dialog` que define un método `createButton()` que es implementado por subclases (`WindowsDialog`, `WebDialog`).  
> - **Abstract Factory:** Un `GUIFactory` que produce componentes (botones, cuadros de texto) para diferentes sistemas operativos.

---

**53. ¿Cómo aplicarías el patrón Strategy en una arquitectura basada en microservicios?**  
- **Strategy:** Permite seleccionar el algoritmo o comportamiento en tiempo de ejecución.  
- **Aplicación:** En un microservicio que envía notificaciones, se puede definir una interfaz `NotificationStrategy` y diferentes implementaciones (correo, SMS, push). En función del contexto, se elige la estrategia adecuada.

> **Ejemplo en Java:**  
> ```java
> public interface NotificationStrategy {
>     void sendNotification(String message);
> }
>
> public class EmailNotification implements NotificationStrategy {
>     public void sendNotification(String message) {
>         // Enviar email
>     }
> }
>
> public class SmsNotification implements NotificationStrategy {
>     public void sendNotification(String message) {
>         // Enviar SMS
>     }
> }
> 
> // Seleccionar la estrategia en función de la configuración:
> NotificationStrategy strategy = (config.isEmail()) ? new EmailNotification() : new SmsNotification();
> strategy.sendNotification("Notificación importante");
> ```

---

## 📡 Kafka

**54. ¿Qué es Apache Kafka y para qué se utiliza?**  
- **Apache Kafka:** Es una plataforma distribuida para el procesamiento y transmisión de eventos en tiempo real.  
- **Uso:** Se emplea para la mensajería, procesamiento de streams, integración de sistemas y arquitectura basada en eventos.

---

**55. ¿Cuáles son los componentes principales de Kafka?**  
- **Producer:** Publica mensajes en topics.  
- **Consumer:** Consume mensajes de topics.  
- **Broker:** Nodo que almacena los mensajes.  
- **Topic:** Categoría de mensajes.  
- **Partition:** Subdivisión de un topic para escalabilidad.  
- **ZooKeeper (o Kafka Raft Metadata en versiones recientes):** Gestiona la metadata del clúster.

---

**56. ¿Cuál es la diferencia entre un broker y un topic en Kafka?**  
- **Broker:** Es el servidor o nodo que ejecuta Kafka y almacena datos.  
- **Topic:** Es una categoría o canal de mensajes dentro del broker.

---

**57. ¿Cómo se garantiza el orden de los mensajes en Kafka?**  
- El orden se garantiza **dentro de cada partición**.  
- Si se requiere un orden global, se debe utilizar una sola partición (lo que afecta la escalabilidad).

> **Ejemplo:**  
> Un topic de órdenes de compra puede tener particiones separadas por región. Dentro de cada partición, el orden de las transacciones se mantiene, pero no necesariamente entre regiones.

---

**58. ¿Cómo escalar un clúster de Kafka?**  
- **Aumentar brokers:** Incrementar el número de nodos para distribuir la carga.  
- **Aumentar particiones:** Permite mayor paralelismo y procesamiento concurrente de mensajes.  
- **Optimización de configuraciones:** Ajustar parámetros como batch size y compresión.

> **Ejemplo:**  
> Si se detecta un alto tráfico en un topic, se puede incrementar el número de particiones para que más consumidores en un consumer group puedan procesar mensajes en paralelo.

---

**59. ¿Cómo proteger Kafka contra accesos no autorizados?**  
- **Autenticación:** Implementar SASL/Kerberos para verificar la identidad de clientes.  
- **Encriptación:** Habilitar TLS/SSL para cifrar la comunicación.  
- **Autorización:** Configurar ACLs (Access Control Lists) para definir qué clientes pueden acceder a qué topics.

> **Ejemplo:**  
> Configurar el broker para requerir TLS y definir ACLs que permitan solo a ciertos grupos de consumidores leer datos de un topic confidencial.

---

**60. ¿Cómo monitorear Kafka y detectar problemas de rendimiento?**  
- **Herramientas de monitoreo:** Integrar Prometheus y Grafana para visualizar métricas (lag de consumers, throughput, tiempos de respuesta).  
- **Logs y alertas:** Configurar alertas en eventos críticos, como fallos de replicación o alta latencia.  
- **Dashboards:** Utilizar dashboards específicos para Kafka que muestran el estado del clúster y la salud de los brokers.

> **Ejemplo:**  
> Configurar un dashboard en Grafana que muestre el lag de cada consumer group para identificar rápidamente cuellos de botella en el procesamiento.

---

## ✅ Testing y Buenas Prácticas

**61. ¿Cuál es la diferencia entre pruebas unitarias, de integración y E2E?**  
- **Pruebas unitarias:** Verifican el funcionamiento de pequeñas unidades de código (métodos o clases) de forma aislada.  
- **Pruebas de integración:** Validan la interacción entre diferentes módulos o servicios.  
- **Pruebas E2E (End-to-End):** Simulan escenarios completos desde la interfaz hasta la base de datos, validando la aplicación en su totalidad.

> **Ejemplo:**  
> Usar JUnit para pruebas unitarias, Spring Boot Test para integración y Selenium para pruebas E2E de una aplicación web.

---

**62. ¿Cómo aplicas el TDD (Test-Driven Development)?**  
- **TDD:** Escribir primero una prueba que falle, luego el código mínimo para que pase la prueba y finalmente refactorizar.  
- **Ciclo:** Red, Green, Refactor.

> **Ejemplo en Java:**  
> 1. Escribir un test que espera que un método `sum(a, b)` retorne la suma.  
> 2. Implementar `sum(a, b)` de forma mínima.  
> 3. Refactorizar el código y los tests según sea necesario.

---

**63. ¿Cómo medir la cobertura de código?**  
- **Herramientas:** Utilizar herramientas como JaCoCo, Cobertura o SonarQube que generan reportes de cobertura de código.  
- **Métricas:** Se miden líneas y ramas cubiertas durante la ejecución de los tests.

> **Ejemplo:**  
> Integrar JaCoCo en el `pom.xml` y ejecutar `mvn test` para generar un reporte en `target/site/jacoco/index.html`.

---

**64. ¿Qué estrategias sigues para versionado semántico y administración de releases?**  
- **SemVer:** Usar la convención *MAJOR.MINOR.PATCH* para indicar cambios incompatibles, nuevas funcionalidades y correcciones, respectivamente.  
- **Releases:** Automatizar el proceso de versiones mediante herramientas CI/CD que incrementen la versión de forma controlada.

> **Ejemplo:**  
> En un proyecto Maven, definir la versión en el `pom.xml` como `1.2.3` y actualizarla según se hagan cambios incompatibles o nuevas features, utilizando plugins como `maven-release-plugin`.

---

**65. ¿Cómo organizas la arquitectura por capas o hexagonal?**  
- **Arquitectura por capas:** Se separa la aplicación en capas (presentación, negocio, persistencia) para lograr bajo acoplamiento y alta cohesión.  
- **Arquitectura hexagonal:** Se centra en la separación del dominio de la infraestructura, permitiendo adaptadores para interactuar con el exterior (bases de datos, APIs, etc.) sin acoplar el dominio.

> **Ejemplo:**  
> Un servicio en Spring Boot que tiene controladores (adaptadores primarios), servicios de dominio y repositorios (adaptadores secundarios), facilitando cambios en la tecnología de persistencia sin afectar la lógica de negocio.

---

**66. ¿Qué prácticas recomiendas para refactorizar grandes módulos sin romper funcionalidad existente?**  
- **Cobertura de tests:** Asegurarse de tener pruebas robustas antes de comenzar la refactorización.  
- **Refactorización incremental:** Realizar cambios pequeños y verificar que el sistema funcione tras cada modificación.  
- **Revisión de código:** Utilizar code reviews para detectar posibles errores en la refactorización.

> **Ejemplo:**  
> Antes de refactorizar un módulo complejo, se crean tests de contrato que aseguran que la funcionalidad permanece igual. Luego, se realizan pequeños cambios y se ejecutan los tests para validar cada paso.

---
