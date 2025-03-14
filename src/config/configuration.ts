export default () => ({
	port: parseInt(process.env.PORT!, 10) || 3000,
	nodeEnv: process.env.NODE_ENV!,

	database: {
		uri: process.env.MONGO_URI,
	},

	redis: {
		host: process.env.REDIS_HOST,
		port: parseInt(process.env.REDIS_PORT!, 10) || 6379,
		password: process.env.REDIS_PASSWORD,
	},

	jwt: {
		accessSecret: process.env.JWT_ACCESS_SECRET,
		refreshSecret: process.env.JWT_REFRESH_SECRET,
		accessExpiresIn: process.env.JWT_ACCESS_EXPIRATION || '15m',
		refreshExpiresIn: process.env.JWT_REFRESH_EXPIRATION || '7d',
	},

	throttle: {
		ttl: parseInt(process.env.THROTTLE_TTL!, 10) || 60,
		limit: parseInt(process.env.THROTTLE_LIMIT!, 10) || 10,
	},

	security: {
		bcryptSaltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS!, 10) || 12,
	},
})
