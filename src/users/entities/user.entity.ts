import * as bcrypt from 'bcryptjs';
import { model, Schema } from "mongoose";
import { UserRole } from "src/common/enums/user-role.enum";
import { User } from "../interfaces/user.interface";

const UserSchema = new Schema<User>(
	{
		email: {
			type: String,
			required: true,
			unique: true,
			trim: true,
			lowercase: true,
		},
		password: {
			type: String,
			required: true,
		},
		firstName: {
			type: String,
			required: true,
			trim: true,
		},
		lastName: {
			type: String,
			required: true,
			trim: true,
		},
		roles: {
			type: [String],
			enum: Object.values(UserRole),
			default: [UserRole.STUDENT],
		},
		isActive: {
			type: Boolean,
			default: true,
		},
		lastLogin: {
			type: Date,
		},
	},
	{
		timestamps: true,
		toJSON: {
			transform: (doc, ret) => {
				delete ret.password;
				return ret;
			},
		},
	},
);

UserSchema.pre('save', async function (next) {
	if (!this.isModified('password')) return next();

	try {
		const salt = await bcrypt.genSalt(12);
		this.password = await bcrypt.hash(this.password, salt);
		next();
	} catch (error) {
		next(error);
	}
});

UserSchema.methods.comparePassword = async function (candidatePassword: string): Promise<boolean> {
	return bcrypt.compare(candidatePassword, this.password);
};

export const UserModel = model<User>('User', UserSchema);
