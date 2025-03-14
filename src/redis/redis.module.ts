import { Global, Module } from '@nestjs/common';
import { ConfigModule } from 'src/config/config.module';
import { redisProviders } from './redis.providers';
import { RedisService } from './redis.service';

@Global()
@Module({
	imports: [ConfigModule],
	providers: [...redisProviders, RedisService],
	exports: [RedisService],
})
export class RedisModule {}
