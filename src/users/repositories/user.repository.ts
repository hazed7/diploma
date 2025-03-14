import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import { Connection, Model } from "mongoose";
import { UserRole } from "src/common/enums/user-role.enum";
import { DATABASE_CONNECTION } from "src/database/database.providers";
import { CreateUserDto } from "../dto/create-user.dto";
import { UpdateUserDto } from "../dto/update-user.dto";
import { UserModel } from "../entities/user.entity";
import { User } from "../interfaces/user.interface";

@Injectable()
export class UserRepository {
	private model: Model<User>;

	constructor(
		@Inject(DATABASE_CONNECTION) private connection: Connection,
	) {
		this.model = this.connection.model<User>('User', UserModel.schema);
	}

	async create(createUserDto: CreateUserDto): Promise<User> {
		const user = new this.model(createUserDto);
		return user.save();
	}

	async findAll(): Promise<User[]> {
		return this.model.find().exec();
	}

	async findOne(id: string): Promise<User> {
		const user = await this.model.findById(id).exec();
		if (!user) {
			throw new NotFoundException(`User with ID "${id}" not found`);
		}

		return user;
	}

	async findByEmail(email: string): Promise<User | null> {
		return this.model.findOne({ email }).exec();
	}

	async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
		const user = await this.model
			.findByIdAndUpdate(id, updateUserDto, { new: true })
			.exec();

		if (!user) {
			throw new NotFoundException(`User with ID "${id}" not found`);
		}

		return user;
	}

	async delete(id: string): Promise<User> {
		const user = await this.model.findByIdAndDelete(id).exec();
		if (!user) {
			throw new NotFoundException(`User with ID "${id}" not found`);
		}

		return user;
	}

	async updateLastLogin(id: string): Promise<void> {
		await this.model.updateOne(
			{ _id: id },
			{ lastLogin: new Date() },
		).exec();
	}

	async addRole(id: string, role: string): Promise<User> {
		const user = await this.model.findById(id).exec();
		if (!user) {
			throw new NotFoundException(`User with ID "${id}" not found`);
		}

		if (!Object.values(UserRole).includes(role as UserRole)) {
			throw new BadRequestException(`Неверная роль: ${role}`);
		}

		const userRole = role as UserRole;
		if (!user.roles.includes(userRole)) {
			user.roles.push(userRole);
			await user.save();
		}

		return user;
	}

	async removeRole(id: string, role: string): Promise<User> {
		const user = await this.model.findById(id).exec();
		if (!user) {
			throw new NotFoundException(`User with ID "${id}" not found`);
		}

		if (!Object.values(UserRole).includes(role as UserRole)) {
			throw new BadRequestException(`Неверная роль: ${role}`);
		}

		const userRole = role as UserRole;

		if (user.roles.includes(userRole)) {
			user.roles = user.roles.filter(r => r !== userRole);
			await user.save();
		}

		return user;
	}
}
