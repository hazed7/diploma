import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus, Logger } from "@nestjs/common";
import { Request, Response } from "express";

interface AuthenticatedRequest extends Request {
	user?: { id?: string | number };
}

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
	private readonly logger = new Logger(HttpExceptionFilter.name);

	catch(exception: HttpException, host: ArgumentsHost) {
		const ctx = host.switchToHttp();
		const response = ctx.getResponse<Response>();
		const request = ctx.getRequest<AuthenticatedRequest>();
		const status = exception.getStatus();

		const errorResponse = {
			statusCode: status,
			timestamp: new Date().toISOString(),
			path: request.url,
			method: request.method,
			message: exception.message || null,
			...(exception.getResponse() as object),
		};

		// log 401 & 403 as warnings
		if (status === HttpStatus.UNAUTHORIZED || status === HttpStatus.FORBIDDEN) {
			this.logger.warn(
				`${request.method} ${request.url} - ${status} - ${JSON.stringify({
					userId: request.user?.id || 'anonymous',
					ip: request.ip,
				})}`,
			);
		} else {
			this.logger.error(
				`${request.method} ${request.url} - ${status}`,
				exception.stack,
			);
		}

		if (process.env.NODE_ENV !== 'production') {
			errorResponse['stack'] = exception.stack;
		}

		response.status(status).json(errorResponse);
	}
}
