import {
	Body,
	Controller,
	Delete,
	Get,
	HttpCode,
	HttpStatus,
	Param,
	Patch,
	Post,
	UseGuards,
} from '@nestjs/common';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { Roles } from '../auth/decorators/roles.decorator';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { UserRole } from '../common/enums/user-role.enum';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './interfaces/user.interface';
import { UsersService } from './users.service';

@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard)
export class UsersController {
	constructor(private readonly usersService: UsersService) {}

	@Post()
	@Roles(UserRole.ADMIN, UserRole.TEACHER)
	async create(@Body() createUserDto: CreateUserDto): Promise<User> {
		return this.usersService.create(createUserDto);
	}

	@Get()
	@Roles(UserRole.ADMIN, UserRole.TEACHER)
	async findAll(): Promise<User[]> {
		return this.usersService.findAll();
	}

	@Get(':id')
	@Roles(UserRole.ADMIN, UserRole.TEACHER)
	async findOne(@Param('id') id: string): Promise<User> {
		return this.usersService.findOne(id);
	}

	@Patch(':id')
	@Roles(UserRole.ADMIN, UserRole.TEACHER)
	async update(
		@Param('id') id: string,
		@Body() updateUserDto: UpdateUserDto,
	): Promise<User> {
		return this.usersService.update(id, updateUserDto);
	}

	@Delete(':id')
	@Roles(UserRole.ADMIN)
	@HttpCode(HttpStatus.NO_CONTENT)
	async remove(@Param('id') id: string): Promise<void> {
		await this.usersService.delete(id);
	}

	@Post(':id/roles/:role')
	@Roles(UserRole.ADMIN)
	async addRole(
		@Param('id') id: string,
		@Param('role') role: UserRole,
		@CurrentUser() currentUser: User,
	): Promise<User> {
		return this.usersService.addRole(id, role, currentUser);
	}

	@Delete(':id/roles/:role')
	@Roles(UserRole.ADMIN)
	async removeRole(
		@Param('id') id: string,
		@Param('role') role: UserRole,
		@CurrentUser() currentUser: User,
	): Promise<User> {
		return this.usersService.removeRole(id, role, currentUser);
	}
}
