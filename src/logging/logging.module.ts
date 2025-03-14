import { Global, Module } from '@nestjs/common';
import { ConfigModule } from '../config/config.module';
import { LoggingService } from './logging.service';

@Global()
@Module({
	imports: [ConfigModule],
	providers: [LoggingService],
	exports: [LoggingService],
})
export class LoggingModule {}
