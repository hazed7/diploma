import { Provider } from '@nestjs/common';
import type { Redis as RedisClient } from 'ioredis';
import Redis from 'ioredis';
import { ConfigService } from 'src/config/config.service';

export const REDIS_CLIENT = 'REDIS_CLIENT';

export const redisProviders: Provider[] = [
	{
		provide: REDIS_CLIENT,
		useFactory: async (configService: ConfigService): Promise<RedisClient> => {
			try {
				const redisConfig = configService.redis;
				const client = new Redis({
					host: redisConfig.host,
					port: redisConfig.port,
					password: redisConfig.password,
					retryStrategy: (times: number) => {
						const delay = Math.min(times * 50, 10000);
						return delay;
					},
					maxRetriesPerRequest: 3,
					enableReadyCheck: true,
				});

				client.on('connect', () => {
					console.log('Redis connected successfully');
				});

				client.on('error', (err: Error & { message: string }) => {
					console.error('Redis error:', err.message);
				});

				return client;
			} catch (error: any) {
				console.error('Redis connection error:', error.messsage);
				throw error;
			}
		},
		inject: [ConfigService],
	}
];
