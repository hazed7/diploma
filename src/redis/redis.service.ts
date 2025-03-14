import { Inject, Injectable, Logger } from "@nestjs/common";
import type { Redis as RedisClient } from 'ioredis';
import { REDIS_CLIENT } from "./redis.providers";

@Injectable()
export class RedisService {
	private readonly logger = new Logger(RedisService.name);

	constructor(@Inject(REDIS_CLIENT) private readonly redisClient: RedisClient) {}

	async storeToken(
		userId: string,
		tokenId: string,
		token: string,
		expiresInSeconds: number,
	): Promise<void> {
		try {
			// store metadata
			const tokenKey = `refresh_token:${tokenId}`;
			await this.redisClient.set(tokenKey, token, 'EX', expiresInSeconds);

			// asst token with user
			await this.redisClient.sadd(`user_tokens:${userId}`, tokenKey);

			await this.redisClient.expire(`user_tokens:${userId}`, expiresInSeconds);
		} catch (error: any) {
			this.logger.error(`Failed to store token: ${error.message}`, error.stack);
			throw new Error('Failed to store token');
		}
	}

	async validateToken(tokenId: string): Promise<string | null> {
		try {
			const tokenKey = `refresh_token:${tokenId}`;
			return await this.redisClient.get(tokenKey);
		} catch (error: any) {
			this.logger.error(`Failed to validate token: ${error.message}`, error.stack);
			throw new Error('Failed to validate token');
		}
	}

	async removeToken(userId: string, tokenId: string): Promise<void> {
		try {
			const tokenKey = `refresh_token:${tokenId}`;

			await this.redisClient.del(tokenKey);
			await this.redisClient.srem(`user_tokens:${userId}`, tokenKey);
		} catch (error: any) {
			this.logger.error(`Failed to remove token: ${error.message}`, error.stack);
			throw new Error('Failed to remove token');
		}
	}

	async removeAllUserTokens(userId: string): Promise<void> {
		try {
			const tokenKeys = await this.redisClient.smembers(`user_tokens:${userId}`);
			if (tokenKeys.length > 0) {
				await this.redisClient.del(...tokenKeys);
			}

			await this.redisClient.del(`user_tokens:${userId}`);
		} catch (error) {
			this.logger.error(`Failed to remove all user tokens: ${error.message}`, error.stack);
			throw new Error('Failed to remove all user tokens');
		}
	}

	async incrementRateLimit(key: string, ttl: number): Promise<number> {
		try {
			const current = await this.redisClient.incr(key);
			if (current === 1) {
				await this.redisClient.expire(key, ttl); // set expire on first req
			}

			return current;
		} catch (error: any) {
			this.logger.error(`Rate limit error: ${error.message}`, error.stack);
			return Number.MAX_SAFE_INTEGER; // safe fail
		}
	}

	async cacheUserSession(userId: string, sessionData: any, ttl: number): Promise<void> {
		try {
			await this.redisClient.set(
				`user_session:${userId}`,
				JSON.stringify(sessionData),
				'EX',
				ttl,
			);
		} catch (error: any) {
			this.logger.error(`Cache user session error: ${error.message}`, error.stack);
		}
	}

	async getUserSession(userId: string): Promise<any | null> {
		try {
			const data = await this.redisClient.get(`user_session:${userId}`);
			return data ? JSON.parse(data) : null;
		} catch (error: any) {
			this.logger.error(`Get user session error: ${error.message}`, error.stack);
			return null;
		}
	}

	async logSecurityEvent(userId: string, event: string, metadata: any): Promise<void> {
		try {
			const logEntry = {
				timestamp: new Date().toISOString(),
				userId,
				event,
				metadata,
			};

			await this.redisClient.lpush(
				`security_logs:${userId}`,
				JSON.stringify(logEntry),
			);

			// keep only last 100 per user
			await this.redisClient.ltrim(`security_logs:${userId}`, 0, 99);

			// set expiry to 30d
			await this.redisClient.expire(`security_logs:${userId}`, 60 * 60 * 24 * 30);
		} catch (error: any) {
			this.logger.error(`Security log error: ${error.message}`, error.stack);
		}
	}
}
