import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as session from 'express-session';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);

    app.enableCors({
        origin: 'http://localhost:5173',
        credentials: true,
        methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    });

    app.use(
        session({
            secret: 'your-secret-key',
            resave: false,
            saveUninitialized: false,
            cookie: {
                secure: process.env.NODE_ENV === 'production',
                maxAge: 1000 * 60 * 60,
                httpOnly: true,
            },
        }),
    );

    await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
