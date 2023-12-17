import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as dotenv from 'dotenv';
import { ValidationPipe } from './validation-pipe/validation-pipe';
import * as express from 'express';

async function bootstrap() {
  dotenv.config();
  const app = await NestFactory.create(AppModule);
  app.enableCors();
  app.useGlobalPipes(new ValidationPipe());
  app.use('/', express.static('/public/build'));
  app.use('/', express.static('/public'));
  await app.listen(process.env.PORT || 4000);
}
bootstrap();
