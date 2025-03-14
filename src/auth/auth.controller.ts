import {
	Body,
	ClassSerializerInterceptor,
	Controller,
	Get,
	HttpCode,
	HttpStatus,
	Post,
	Req,
	Res,
	UseGuards,
	UseInterceptors,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ThrottleGuard } from '../common/guards/throttle.guard';
import { User } from '../users/interfaces/user.interface';
import { AuthService } from './auth.service';
import { CurrentUser } from './decorators/current-user.decorator';
import { Public } from './decorators/public.decorator';
import { RegisterDto } from './dto/register.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';
import { LocalAuthGuard } from './guards/local-auth.guard';

@Controller('auth')
@UseInterceptors(ClassSerializerInterceptor)
export class AuthController {
	constructor(private authService: AuthService) {}

	@Public()
	@Post('register')
	@UseGuards(ThrottleGuard)
	async register(
		@Body() registerDto: RegisterDto,
		@Req() req: Request,
		@Res({ passthrough: true }) res: Response,
	): Promise<{ accessToken: string }> {
		const ip = req.ip || 'unknown';
		const userAgent =
			Array.isArray(req.headers['user-agent'])
				? req.headers['user-agent'][0]
				: req.headers['user-agent'] || 'unknown';

		const tokens = await this.authService.register(registerDto, ip, userAgent);

		this.setRefreshTokenCookie(res, tokens.refreshToken);

		return {
			accessToken: tokens.accessToken,
		};
	}

	@Public()
	@UseGuards(LocalAuthGuard, ThrottleGuard)
	@Post('login')
	@HttpCode(HttpStatus.OK)
	async login(
		@Req() req: Request,
		@Res({ passthrough: true }) res: Response,
	): Promise<{ accessToken: string }> {
		const ip = req.ip || 'unknown';
		const userAgent = req.headers['user-agent'] || 'unknown';

		const tokens = await this.authService.login(req.user as User, userAgent, ip);

		this.setRefreshTokenCookie(res, tokens.refreshToken);

		return {
			accessToken: tokens.accessToken,
		};
	}

	@UseGuards(JwtAuthGuard)
	@Post('logout')
	@HttpCode(HttpStatus.OK)
	async logout(
		@CurrentUser() user: User,
		@Req() req: Request,
		@Res({ passthrough: true }) res: Response,
	): Promise<{ message: string }> {
		try {
			const authHeader = req.headers.authorization;

			if (authHeader) {
				const token = authHeader.split(' ')[1];
				const decodedToken = this.parseJwt(token);

				if (decodedToken && decodedToken.tokenId) {
					await this.authService.logout(String(user._id), decodedToken.tokenId);
				}
			}

			// clear refresh token cookie
			this.clearRefreshTokenCookie(res);

			return { message: 'Logged out successfully' };
		} catch (error) {
			this.clearRefreshTokenCookie(res);

			return { message: 'Logged out successfully' };
		}
	}

	@UseGuards(JwtAuthGuard)
	@Post('logout-all')
	@HttpCode(HttpStatus.OK)
	async logoutAll(
		@CurrentUser() user: User,
		@Res({ passthrough: true }) res: Response,
	): Promise<{ message: string }> {
		await this.authService.logoutAll(String(user._id));

		this.clearRefreshTokenCookie(res);

		return { message: 'Logged out from all devices successfully' };
	}

	@Public()
	@UseGuards(JwtRefreshGuard, ThrottleGuard)
	@Post('refresh')
	@HttpCode(HttpStatus.OK)
	async refresh(
		@Req() req: Request,
		@Res({ passthrough: true }) res: Response,
	): Promise<{ accessToken: string }> {
		const user = req.user as { userId: string; tokenId: string };

		const tokens = await this.authService.refreshTokens(user.userId, user.tokenId);

		this.setRefreshTokenCookie(res, tokens.refreshToken);

		return {
			accessToken: tokens.accessToken,
		};
	}

	@UseGuards(JwtAuthGuard)
	@Post('change-password')
	@HttpCode(HttpStatus.OK)
	async changePassword(
		@CurrentUser() user: User,
		@Body() body: { currentPassword: string; newPassword: string },
		@Res({ passthrough: true }) res: Response,
	): Promise<{ message: string }> {
		await this.authService.changePassword(
			String(user._id),
			body.currentPassword,
			body.newPassword,
		);

		this.clearRefreshTokenCookie(res);

		return { message: 'Password changed successfully. Please log in again.' };
	}

	@UseGuards(JwtAuthGuard)
	@Get('me')
	@HttpCode(HttpStatus.OK)
	async getProfile(@CurrentUser() user: User): Promise<User> {
		return user;
	}

	private setRefreshTokenCookie(res: Response, token: string): void {
		res.cookie('refresh_token', token, {
			httpOnly: true,
			sameSite: 'strict',
			secure: process.env.NODE_ENV === 'production',
			maxAge: 7 * 24 * 60 * 60 * 1000, // 7d
			path: '/auth/refresh',
		});
	}

	private clearRefreshTokenCookie(res: Response): void {
		res.cookie('refresh_token', '', {
			httpOnly: true,
			sameSite: 'strict',
			secure: process.env.NODE_ENV === 'production',
			expires: new Date(0),
			path: '/auth/refresh',
		});
	}

	private parseJwt(token: string): any {
		try {
			const base64Url = token.split('.')[1];
			const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
			const jsonPayload = decodeURIComponent(
				atob(base64)
					.split('')
					.map(c => `%${`00${c.charCodeAt(0).toString(16)}`.slice(-2)}`)
					.join(''),
			);

			return JSON.parse(jsonPayload);
		} catch (error) {
			return null;
		}
	}
}
