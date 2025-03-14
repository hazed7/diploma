import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty, IsOptional, IsString, IsArray, IsEnum, MinLength } from "class-validator";
import { UserRole } from "src/common/enums/user-role.enum";

export class UpdateUserDto {
	@ApiProperty({
		description: 'Электронная почта пользователя',
		example: 'user@example.com',
		required: false,
	})
	@IsEmail()
	@IsNotEmpty()
	@IsOptional()
	email?: string;

	@ApiProperty({
		description: 'Имя пользователя',
		example: 'Иван',
		required: false,
	})
	@IsString()
	@IsNotEmpty()
	@IsOptional()
	firstName?: string;

	@ApiProperty({
		description: 'Фамилия пользователя',
		example: 'Иванов',
		required: false,
	})
	@IsString()
	@IsNotEmpty()
	@IsOptional()
	lastName?: string;

	@ApiProperty({
		description: 'Роли пользователя',
		enum: UserRole,
		isArray: true,
		required: false,
		default: [UserRole.STUDENT],
	})
	@IsArray()
	@IsOptional()
	@IsEnum(UserRole, { each: true })
	roles?: UserRole[];

	@ApiProperty({
		description: 'Пароль пользователя (минимум 8 символов)',
		required: false,
	})
	@IsString()
	@MinLength(8)
	@IsOptional()
	password?: string;
}
