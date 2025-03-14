import { Provider } from "@nestjs/common";
import { Connection, createConnection } from "mongoose";
import { ConfigService } from "src/config/config.service";

export const DATABASE_CONNECTION = 'DATABASE_CONNECTION';

export const databaseProviders: Provider[] = [
	{
		provide: DATABASE_CONNECTION,
		useFactory: async (configService: ConfigService): Promise<Connection> => {
			try {
				const connection = createConnection(configService.database.uri, {
				});

				console.log('MongoDB connected successfully');
				return connection;
			} catch (error) {
				console.error('MongoDB connection error:', error.message);
				throw error;
			}
		},
		inject: [ConfigService],
	},
];
