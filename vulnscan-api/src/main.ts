import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // 🔒 Hardening con Helmet (sin 'unsafe-inline')
  app.use(
    helmet({
      // CSP fuerte (no incluye 'unsafe-inline')
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          // Como es un API, esto es súper restrictivo y seguro:
          defaultSrc: ["'self'"],
          baseUri: ["'self'"],
          objectSrc: ["'none'"],
          frameAncestors: ["'none'"],
          // Si más adelante sirves HTML con JS/CSS de terceros,
          // agrega aquí dominios explícitos en scriptSrc/styleSrc.
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          imgSrc: ["'self'", "data:"],
          connectSrc: ["'self'"],
          // Opcionalmente puedes activar upgrade de HTTP→HTTPS:
          // upgradeInsecureRequests: [],
        },
      },
      crossOriginOpenerPolicy: { policy: 'same-origin' },      // COOP
      crossOriginEmbedderPolicy: true,                         // COEP: require-corp
      crossOriginResourcePolicy: { policy: 'same-site' },      // CORP
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      // X-Content-Type-Options: nosniff, X-DNS-Prefetch-Control, etc. vienen por defecto
    })
  );

  // 🛡️ HSTS + Permissions-Policy + X-Frame-Options
  // (HSTS solo tiene efecto real sobre HTTPS en producción)
  app.use((req, res, next) => {
    // HSTS: 1 año + subdominios + preload
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    // Bloquear permisos del navegador por defecto
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    // Redundante con frame-ancestors, pero útil para compatibilidad
    res.setHeader('X-Frame-Options', 'DENY');
    next();
  });

  // 🌐 CORS para tu Angular (localhost:4200)
  // Si en producción expones el API a otro origen, agrega aquí ese origen.
  app.enableCors({
    origin: ['http://localhost:4200'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    // allowedHeaders, credentials, etc., si los necesitas
  });

  const port = process.env.PORT ? Number(process.env.PORT) : 3000;
  await app.listen(port);
  console.log(`🚀 Backend corriendo en http://localhost:${port}`);
}
bootstrap();
