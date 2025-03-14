import { Document } from 'mongoose';
import { UserRole } from 'src/common/enums/user-role.enum';

export interface User extends Document {
	email: string;
	password: string;
	firstName: string;
	lastName: string;
	roles: UserRole[];
	isActive: boolean;
	lastLogin: Date;
	createdAt: Date;
	updatedAt: Date;
	comparePassword: (candidatePassword: string) => Promise<boolean>;
}
