import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '../../config/config.service';
import { RedisService } from '../../redis/redis.service';
import { UsersService } from '../../users/users.service';
import { JwtPayload } from '../interfaces/jwt-payload.interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
	constructor(
		private configService: ConfigService,
		private usersService: UsersService,
		private redisService: RedisService,
	) {
		super({
			jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
			ignoreExpiration: false,
			secretOrKey: configService.jwt.accessSecret,
		});
	}

	async validate(payload: JwtPayload) {
		try {
			// try to get user from cache
			const cachedUser = await this.redisService.getUserSession(payload.sub);
			if (cachedUser) {
				return cachedUser;
			}

			// if not in cache, get from db
			const user = await this.usersService.findOne(payload.sub);
			if (!user || !user.isActive) {
				throw new UnauthorizedException();
			}

			// cache user
			const ttl = payload.exp ? payload.exp - Math.floor(Date.now() / 1000) : 900; // 15 minutes default
			await this.redisService.cacheUserSession(payload.sub, user, ttl);

			return user;
		} catch (error) {
			throw new UnauthorizedException();
		}
	}
}
