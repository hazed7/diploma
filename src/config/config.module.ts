import { Module } from "@nestjs/common";
import { ConfigService, ConfigModule as NestConfigModule } from '@nestjs/config';
import configuration from "./configuration";

@Module({
	imports: [
		NestConfigModule.forRoot({
			isGlobal: true,
			load: [configuration],
			validationSchema: {
				abortEarly: false,
			},
			expandVariables: true,
		}),
	],
	providers: [ConfigService],
	exports: [ConfigService],
})
export class ConfigModule {}
