import { Injectable } from "@nestjs/common";
import { ConfigService as NestConfigService } from '@nestjs/config';

@Injectable()
export class ConfigService {
	constructor(private configService: NestConfigService) {}

	get<T>(key: string): T {
		return this.configService.get<T>(key)!;
	}

	get nodeEnv(): string {
		return this.get<string>('nodeEnv');
	}

	get port(): number {
		return this.get<number>('port');
	}

	get database() {
		return {
			uri: this.get<string>('database.uri'),
		};
	}

	get redis() {
		return {
			host: this.get<string>('redis.host'),
			port: this.get<number>('redis.port'),
			password: this.get<string>('redis.password'),
		};
	}

	get jwt() {
		return {
			accessSecret: this.get<string>('jwt.accessSecret'),
			refreshSecret: this.get<string>('jwt.refreshSecret'),
			accessExpiresIn: this.get<string>('jwt.accessExpiresIn'),
			refreshExpiresIn: this.get<string>('jwt.refreshExpiresIn'),
		};
	}

	get throttle() {
		return {
			ttl: this.get<number>('throttle.ttl'),
			limit: this.get<number>('throttle.limit'),
		};
	}

	get security() {
		return {
			bcryptSaltRounds: this.get<number>('security.bcryptSaltRounds'),
		};
	}
}
