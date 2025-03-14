import { CanActivate, ExecutionContext, HttpException, HttpStatus, Injectable } from "@nestjs/common";
import { ConfigService } from "src/config/config.service";
import { RedisService } from "src/redis/redis.service";

@Injectable()
export class ThrottleGuard implements CanActivate {
	constructor(
		private readonly redisService: RedisService,
		private readonly configService: ConfigService,
	) {}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const request = context.switchToHttp().getRequest();
		const ip = request.ip;

		// construct path-specific limiting
		const path = request.route?.path || request.url;
		const method = request.method;
		const key = `ratelimit:${method}:${path}:${ip}`;

		const { ttl, limit } = this.configService.throttle;

		const count = await this.redisService.incrementRateLimit(key, ttl);

		// add headers
		const response = context.switchToHttp().getResponse();
		response.header('X-RateLimit-Limit', limit);
		response.header('X-RateLimit-Remaining', Math.max(0, limit - count));

		if (count > limit) {
			throw new HttpException('Too Many Requests', HttpStatus.TOO_MANY_REQUESTS);
		}

		return true;
	}
}
