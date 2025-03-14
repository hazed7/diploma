import Joi from 'joi';

export const validationSchema = Joi.object({
	NODE_ENV: Joi.string()
		.valid('development', 'production', 'test')
		.default('development'),
	PORT: Joi.number().default(3000),

	// mongo
	MONGO_URI: Joi.string().required(),

	// redis
	REDIS_HOST: Joi.string().required(),
	REDIS_PORT: Joi.number().default(6379),
	REDIS_PASSWORD: Joi.string().required(),

	// jwt
	JWT_ACCESS_SECRET: Joi.string().required(),
	JWT_REFRESH_SECRET: Joi.string().required(),
	JWT_ACCESS_EXPIRATION: Joi.string().default('15m'),
	JWT_REFRESH_EXPIRATION: Joi.string().default('7d'),

	// rate limiting
	THROTTLE_TTL: Joi.number().default(60),
	THROTTLE_LIMIT: Joi.number().default(10),

	// security
	BCRYPT_SALT_ROUND: Joi.number().default(12),
});
