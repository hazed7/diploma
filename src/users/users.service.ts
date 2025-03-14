import { ConflictException, ForbiddenException, Injectable, NotFoundException, UnauthorizedException } from "@nestjs/common";
import * as bcrypt from 'bcryptjs';
import { UserRole } from "src/common/enums/user-role.enum";
import { ConfigService } from "src/config/config.service";
import { CreateUserDto } from "./dto/create-user.dto";
import { UpdateUserDto } from "./dto/update-user.dto";
import { User } from "./interfaces/user.interface";
import { UserRepository } from "./repositories/user.repository";

@Injectable()
export class UsersService {
	constructor(
		private readonly userRepository: UserRepository,
		private readonly configService: ConfigService,
	) {}

	async create(createUserDto: CreateUserDto): Promise<User> {
		const existingUser = await this.userRepository.findByEmail(createUserDto.email);
		if (existingUser) {
			throw new ConflictException('User with this email already exists');
		}

		return this.userRepository.create(createUserDto);
	}

	async findAll(): Promise<User[]> {
		return this.userRepository.findAll();
	}

	async findOne(id: string): Promise<User> {
		return this.userRepository.findOne(id);
	}

	async findByEmail(email: string): Promise<User> {
		const user = await this.userRepository.findByEmail(email);

		if (!user) {
			throw new NotFoundException(`User with email "${email}" not found`);
		}

		return user;
	}

	async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
		return this.userRepository.update(id, updateUserDto);
	}

	async delete(id: string): Promise<User> {
		return this.userRepository.delete(id);
	}

	async updateLastLogin(id: string): Promise<void> {
		await this.userRepository.updateLastLogin(id);
	}

	async setPassword(id: string, newPassword: string): Promise<void> {
		const user = await this.userRepository.findOne(id);

		const salt = await bcrypt.genSalt(this.configService.security.bcryptSaltRounds);
		const hashedPassword = await bcrypt.hash(newPassword, salt);

		await this.userRepository.update(id, { password: hashedPassword });
	}

	async addRole(id: string, role: UserRole, currentUser: User): Promise<User> {
		if (!currentUser.roles.includes(UserRole.ADMIN)) {
			throw new ForbiddenException('Only admins can add roles');
		}

		return this.userRepository.addRole(id, role);
	}

	async removeRole(id: string, role: UserRole, currentUser: User): Promise<User> {
		if (!currentUser.roles.includes(UserRole.ADMIN)) {
			throw new ForbiddenException('Only admins can remove roles');
		}

		const user = await this.userRepository.findOne(id);
		if (user.roles.length === 1 && user.roles.includes(role)) {
			throw new ForbiddenException('Cannot remove the last role from a user');
		}

		return this.userRepository.removeRole(id, role);
	}

	async validateUser(email: string, password: string): Promise<User> {
		const user = await this.userRepository.findByEmail(email);
		if (!user) {
			throw new UnauthorizedException('Invalid credentials');
		}
		if (!user.isActive) {
			throw new UnauthorizedException('User account is inactive');
		}

		const isPasswordValid = await user.comparePassword(password);
		if (!isPasswordValid) {
			throw new UnauthorizedException('Invalid credentials');
		}

		return user;
	}

	async checkUserHasRoles(userId: string, requiredRoles: UserRole[]): Promise<boolean> {
		const user = await this.userRepository.findOne(userId);
		if (!user.isActive) {
			return false;
		}

		return requiredRoles.some(role => user.roles.includes(role));
	}
}
