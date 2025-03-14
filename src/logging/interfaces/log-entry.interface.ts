export interface LogEntry {
	context: string;
	message: string;
	level: string;
	timestamp: Date;
	userId?: string;
	metadata?: Record<string, any>;
}
