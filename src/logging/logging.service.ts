import { Injectable, LoggerService as NestLoggerService, Scope } from '@nestjs/common';
import * as winston from 'winston';
import { ConfigService } from '../config/config.service';
import { LogEntry } from './interfaces/log-entry.interface';

@Injectable({ scope: Scope.TRANSIENT })
export class LoggingService implements NestLoggerService {
	private context: string;
	private logger: winston.Logger;

	constructor(private configService: ConfigService) {
		this.initializeLogger();
	}

	private initializeLogger() {
		const { combine, timestamp, printf, colorize } = winston.format;

		const logFormat = printf(({ level, message, timestamp, context, ...meta }) => {
			return `${timestamp} [${level}] [${context || 'Application'}]: ${message} ${Object.keys(meta).length ? JSON.stringify(meta) : ''
				}`;
		});

		this.logger = winston.createLogger({
			level: this.configService.nodeEnv === 'production' ? 'info' : 'debug',
			format: combine(
				timestamp(),
				logFormat,
			),
			defaultMeta: { service: 'lms-service' },
			transports: [
				new winston.transports.Console({
					format: combine(
						colorize(),
						timestamp(),
						logFormat,
					),
				}),
			],
		});

		if (this.configService.nodeEnv === 'production') {
			this.logger.add(
				new winston.transports.File({
					filename: 'logs/error.log',
					level: 'error',
					maxsize: 10485760, // 10mb
					maxFiles: 5,
				}),
			);

			this.logger.add(
				new winston.transports.File({
					filename: 'logs/combined.log',
					maxsize: 10485760, // 10mb
					maxFiles: 5,
				}),
			);
		}
	}

	setContext(context: string) {
		this.context = context;
		return this;
	}

	error(message: string, trace?: string, context?: string): void {
		const entry: LogEntry = {
			message,
			context: context || this.context,
			level: 'error',
			timestamp: new Date(),
			metadata: trace ? { trace } : undefined,
		};

		this.logger.error(message, {
			context: entry.context,
			trace,
		});
	}

	warn(message: string, context?: string): void {
		const entry: LogEntry = {
			message,
			context: context || this.context,
			level: 'warn',
			timestamp: new Date(),
		};

		this.logger.warn(message, {
			context: entry.context,
		});
	}

	log(message: string, context?: string): void {
		const entry: LogEntry = {
			message,
			context: context || this.context,
			level: 'info',
			timestamp: new Date(),
		};

		this.logger.info(message, {
			context: entry.context,
		});
	}

	debug(message: string, context?: string): void {
		const entry: LogEntry = {
			message,
			context: context || this.context,
			level: 'debug',
			timestamp: new Date(),
		};

		this.logger.debug(message, {
			context: entry.context,
		});
	}

	verbose(message: string, context?: string): void {
		const entry: LogEntry = {
			message,
			context: context || this.context,
			level: 'verbose',
			timestamp: new Date(),
		};

		this.logger.verbose(message, {
			context: entry.context,
		});
	}

	security(message: string, userId: string, metadata?: Record<string, any>, context?: string): void {
		const entry: LogEntry = {
			message,
			context: context || this.context,
			level: 'info',
			timestamp: new Date(),
			userId,
			metadata,
		};

		this.logger.info(`[SECURITY] ${message}`, {
			context: entry.context,
			userId,
			...metadata,
		});
	}

	audit(message: string, userId: string, action: string, resource: string, metadata?: Record<string, any>, context?: string): void {
		const entry: LogEntry = {
			message,
			context: context || this.context,
			level: 'info',
			timestamp: new Date(),
			userId,
			metadata: {
				...metadata,
				action,
				resource,
			},
		};

		this.logger.info(`[AUDIT] ${message}`, {
			context: entry.context,
			userId,
			action,
			resource,
			...metadata,
		});
	}
}
