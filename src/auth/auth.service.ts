import {
	BadRequestException,
	ConflictException,
	Injectable,
	Logger,
	UnauthorizedException
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import { ConfigService } from '../config/config.service';
import { RedisService } from '../redis/redis.service';
import { User } from '../users/interfaces/user.interface';
import { UsersService } from '../users/users.service';
import { RegisterDto } from './dto/register.dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { Tokens } from './interfaces/tokens.interface';

@Injectable()
export class AuthService {
	private readonly logger = new Logger(AuthService.name);

	constructor(
		private usersService: UsersService,
		private jwtService: JwtService,
		private configService: ConfigService,
		private redisService: RedisService,
	) {}

	async validateUser(email: string, password: string): Promise<User> {
		try {
			return await this.usersService.validateUser(email, password);
		} catch (error) {
			this.logger.warn(`Failed login attempt for email: ${email}`);
			throw new UnauthorizedException('Invalid credentials');
		}
	}

	async register(registerDto: RegisterDto, ip: string, userAgent: string): Promise<Tokens> {
		try {
			const existingUser = await this.usersService.findByEmail(registerDto.email).catch(() => null);
			if (existingUser) {
				throw new ConflictException('User with this email already exists');
			}

			const user = await this.usersService.create({
				email: registerDto.email,
				password: registerDto.password,
				firstName: registerDto.firstName,
				lastName: registerDto.lastName,
			});

			const tokens = await this.generateTokens(user);

			await this.redisService.logSecurityEvent(
				String(user._id),
				'user_registered',
				{
					ip,
					userAgent,
				},
			);

			return tokens;
		} catch (error) {
			if (error instanceof ConflictException) {
				throw error;
			}

			this.logger.error(`Registration error: ${error.message}`, error.stack);
			throw new BadRequestException('Registration failed');
		}
	}

	async login(user: User, userAgent: string, ip: string): Promise<Tokens> {
		try {
			await this.usersService.updateLastLogin(String(user._id));

			const tokens = await this.generateTokens(user);

			await this.redisService.logSecurityEvent(String(user._id), 'user_login', {
				ip,
				userAgent,
			});

			return tokens;
		} catch (error) {
			this.logger.error(`Login error: ${error.message}`, error.stack);
			throw new UnauthorizedException('Login failed');
		}
	}

	async refreshTokens(userId: string, tokenId: string): Promise<Tokens> {
		try {
			const user = await this.usersService.findOne(userId);
			if (!user || !user.isActive) {
				throw new UnauthorizedException('User not found or inactive');
			}

			// remove old refresh token
			await this.redisService.removeToken(userId, tokenId);

			// generate new tokens
			const tokens = await this.generateTokens(user);

			await this.redisService.logSecurityEvent(userId, 'token_refreshed', {
				oldTokenId: tokenId,
				newTokenId: tokens.refreshToken.split('.')[2], // TODO: make it secure
			});

			return tokens;
		} catch (error) {
			this.logger.error(`Refresh tokens error: ${error.message}`, error.stack);
			throw new UnauthorizedException('Failed to refresh tokens');
		}
	}

	async logout(userId: string, tokenId: string): Promise<void> {
		try {
			await this.redisService.removeToken(userId, tokenId);

			await this.redisService.logSecurityEvent(userId, 'user_logout', {
				tokenId,
			});
		} catch (error) {
			this.logger.error(`Logout error: ${error.message}`, error.stack);
		}
	}

	async logoutAll(userId: string): Promise<void> {
		try {
			await this.redisService.removeAllUserTokens(userId);

			await this.redisService.logSecurityEvent(userId, 'user_logout_all', {});
		} catch (error) {
			this.logger.error(`Logout all error: ${error.message}`, error.stack);
		}
	}

	async changePassword(
		userId: string,
		currentPassword: string,
		newPassword: string,
	): Promise<void> {
		try {
			const user = await this.usersService.findOne(userId);

			const isPasswordValid = await user.comparePassword(currentPassword);
			if (!isPasswordValid) {
				throw new UnauthorizedException('Current password is incorrect');
			}

			// update password
			await this.usersService.setPassword(userId, newPassword);

			// revoke all tokens
			await this.redisService.removeAllUserTokens(userId);

			await this.redisService.logSecurityEvent(userId, 'password_changed', {});
		} catch (error) {
			if (error instanceof UnauthorizedException) {
				throw error;
			}

			this.logger.error(`Change password error: ${error.message}`, error.stack);
			throw new BadRequestException('Failed to change password');
		}
	}

	private async generateTokens(user: User): Promise<Tokens> {
		try {
			const tokenId = uuidv4();

			const payload: JwtPayload = {
				sub: String(user._id),
				username: user.email,
				roles: user.roles,
				tokenId,
			};

			// gen tokens
			const [accessToken, refreshToken] = await Promise.all([
				this.jwtService.signAsync(payload, {
					secret: this.configService.jwt.accessSecret,
					expiresIn: this.configService.jwt.accessExpiresIn,
				}),
				this.jwtService.signAsync(payload, {
					secret: this.configService.jwt.refreshSecret,
					expiresIn: this.configService.jwt.refreshExpiresIn,
				}),
			]);

			const refreshExpiresInSeconds = this.parseExpiresIn(this.configService.jwt.refreshExpiresIn);

			await this.redisService.storeToken(
				String(user._id),
				tokenId,
				refreshToken,
				refreshExpiresInSeconds,
			);

			return {
				accessToken,
				refreshToken,
			};
		} catch (error) {
			this.logger.error(`Generate tokens error: ${error.message}`, error.stack);
			throw new Error('Failed to generate tokens');
		}
	}

	private parseExpiresIn(expiresIn: string): number {
		const unit = expiresIn.slice(-1);
		const value = parseInt(expiresIn.slice(0, -1), 10);

		switch (unit) {
			case 's':
				return value;
			case 'm':
				return value * 60;
			case 'h':
				return value * 60 * 60;
			case 'd':
				return value * 60 * 60 * 24;
			default:
				return 7 * 24 * 60 * 60; // 7d
		}
	}
}
