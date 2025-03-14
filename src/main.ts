import { Logger, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { LoggingInterceptor } from './common/interceptors/logging.interceptor';
import { TransformInterceptor } from './common/interceptors/transform.interceptor';
import { ConfigService } from './config/config.service';

async function bootstrap() {
	const app = await NestFactory.create(AppModule, {
		logger: ['error', 'warn', 'log', 'debug', 'verbose'],
	});

	const configService = app.get(ConfigService);
	const port = configService.port;
	const env = configService.nodeEnv;

	app.use(helmet());
	app.use(cookieParser());

	// CORS
	app.enableCors({
		origin: env === 'production' ? [/\.yourdomain\.com$/] : true,
		credentials: true,
	});

	app.useGlobalPipes(
		new ValidationPipe({
			whitelist: true,
			forbidNonWhitelisted: true,
			transform: true,
			transformOptions: {
				enableImplicitConversion: true,
			},
		}),
	);

	app.useGlobalFilters(new HttpExceptionFilter());
	app.useGlobalInterceptors(new TransformInterceptor(), new LoggingInterceptor());
	app.setGlobalPrefix('api/v1');

	// // swagger API documentation
	// if (env !== 'production') {
	// 	const config = new DocumentBuilder()
	// 		.setTitle('EMS API')
	// 		.setVersion('1.0')
	// 		.addBearerAuth()
	// 		.build();

	// 	const document = SwaggerModule.createDocument(app, config);
	// 	SwaggerModule.setup('api/docs', app, document);
	// }

	// start server
	await app.listen(port);

	Logger.log(
		`Application is running on: http://localhost:${port}/api/v1`,
		'Bootstrap',
	);

	if (env !== 'production') {
		Logger.log(
			`Swagger documentation is available at: http://localhost:${port}/api/docs`,
			'Bootstrap',
		);
	}
}

bootstrap();
