import { CallHandler, ExecutionContext, Injectable, Logger, NestInterceptor } from "@nestjs/common";
import { Observable } from "rxjs";
import { tap } from 'rxjs/operators';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
	private readonly logger = new Logger(LoggingInterceptor.name);

	intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
		const request = context.switchToHttp().getRequest();
		const { method, url, ip, user } = request;
		const userId = user?.id || 'anonymous';
		const userAgent = request.headers['user-agent'] || 'unknown';

		const now = Date.now();

		return next.handle().pipe(
			tap({
				next: () => {
					const response = context.switchToHttp().getResponse();
					const delay = Date.now() - now;
					this.logger.log(
						`${method} ${url} ${response.statusCode} ${delay}ms - User: ${userId} - IP: ${ip} - UA: ${userAgent}`
					);
				},
				error: (error) => {
					const delay = Date.now() - now;
					this.logger.error(
						`${method} ${url} ERROR ${delay}ms - User: ${userId} - IP: ${ip}`,
						error.stack,
					);
				},
			}),
		);
	}
}
