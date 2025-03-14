import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '../../config/config.service';
import { RedisService } from '../../redis/redis.service';
import { JwtPayload } from '../interfaces/jwt-payload.interface';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
	constructor(
		private configService: ConfigService,
		private redisService: RedisService,
	) {
		super({
			jwtFromRequest: ExtractJwt.fromExtractors([
				(request: Request) => {
					// extract from cookie
					const refreshToken = request?.cookies?.['refresh_token'];
					return refreshToken;
				},
			]),
			ignoreExpiration: false,
			secretOrKey: configService.jwt.refreshSecret,
			passReqToCallback: true,
		});
	}

	async validate(req: Request, payload: JwtPayload) {
		// get token from cookie
		const refreshToken = req.cookies['refresh_token'];
		if (!refreshToken) {
			throw new UnauthorizedException('Refresh token not found');
		}

		// validate in redis
		const storedToken = await this.redisService.validateToken(payload.tokenId);
		if (!storedToken || storedToken !== refreshToken) {
			throw new UnauthorizedException('Invalid refresh token');
		}

		return {
			userId: payload.sub,
			tokenId: payload.tokenId,
		};
	}
}
