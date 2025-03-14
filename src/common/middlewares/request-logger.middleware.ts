import { Injectable, Logger, NestMiddleware } from "@nestjs/common";
import { NextFunction, Request, Response } from "express";

@Injectable()
export class RequestLoggerMiddleware implements NestMiddleware {
	private readonly logger = new Logger('HTTP');

	use(req: Request, res: Response, next: NextFunction) {
		const { ip, method, originalUrl } = req;
		const userAgent = req.get('user-agent') || '';

		this.logger.log(
			`${method} ${originalUrl} - ${ip} - ${userAgent}`,
		);

		const start = Date.now();

		res.on('finish', () => {
			const { statusCode } = res;
			const contentLength = res.get('content-length') || 0;
			const responseTime = Date.now() - start;

			if (statusCode >= 400) {
				this.logger.error(
					`${method} ${originalUrl} ${statusCode} ${responseTime}ms ${contentLength} - ${ip} - ${userAgent}`,
				);
			} else if (statusCode >= 300) {
				this.logger.warn(
					`${method} ${originalUrl} ${statusCode} ${responseTime}ms ${contentLength} - ${ip} - ${userAgent}`,
				);
			} else {
				this.logger.log(
					`${method} ${originalUrl} ${statusCode} ${responseTime}ms ${contentLength} - ${ip} - ${userAgent}`,
				);
			}
		});

		next();
	}
}
