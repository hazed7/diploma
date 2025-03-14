export interface JwtPayload {
	sub: string;  // user ID
	username: string;  // user email
	roles: string[];
	tokenId: string;
	iat?: number;
	exp?: number;
}
