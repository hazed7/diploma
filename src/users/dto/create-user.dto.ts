import { ApiProperty } from '@nestjs/swagger';
import { IsArray, IsEmail, IsEnum, IsNotEmpty, IsOptional, IsString, MinLength } from 'class-validator';
import { UserRole } from 'src/common/enums/user-role.enum';

export class CreateUserDto {
	@ApiProperty({
		description: 'Электронная почта пользователя',
		example: 'user@example.com',
	})
	@IsEmail()
	@IsNotEmpty()
	email: string;

	@ApiProperty({
		description: 'Пароль пользователя (минимум 8 символов)',
		example: 'strongPassword123',
	})
	@IsString()
	@MinLength(8)
	@IsNotEmpty()
	password: string;

	@ApiProperty({
		description: 'Имя пользователя',
		example: 'Иван',
	})
	@IsString()
	@IsNotEmpty()
	firstName: string;

	@ApiProperty({
		description: 'Фамилия пользователя',
		example: 'Иванов',
	})
	@IsString()
	@IsNotEmpty()
	lastName: string;

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
	roles?: UserRole[] = [UserRole.STUDENT];
}
