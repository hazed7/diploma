import { IsEmail, IsNotEmpty, IsOptional, IsString, Matches, MinLength } from 'class-validator';

export class RegisterDto {
	@IsEmail()
	@IsNotEmpty()
	email: string;

	@IsString()
	@MinLength(8)
	@IsNotEmpty()
	@Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
		message: 'Password is too weak - must contain uppercase, lowercase, and number/special character',
	})
	password: string;

	@IsString()
	@IsNotEmpty()
	firstName: string;

	@IsString()
	@IsNotEmpty()
	lastName: string;

	@IsString()
	@IsOptional()
	inviteCode?: string;
}
