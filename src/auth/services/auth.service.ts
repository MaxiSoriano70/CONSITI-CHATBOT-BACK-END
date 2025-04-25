import { Injectable, ConflictException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { User } from '../models/user.schema';
import { PayloadToken } from '../models/token.model';
import * as bcrypt from 'bcrypt';
import { CreateUserDto } from '../dtos/create-user.dto';
import { UserRole } from '../enums/user-role.enum';

@Injectable()
export class AuthService {
    constructor(
        private jwtService: JwtService,
        @InjectModel(User.name) private userModel: Model<User>,
    ) {}

    async validateUser(email: string, password: string): Promise<User | null> {
        const user = await this.userModel.findOne({ email }).select('+password');

        if (!user) {
            return null;
        }

        const isPasswordValid = await bcrypt.compare(password, user.password!);

        if (isPasswordValid) {
            return user;
        }

        return null;
    }

    generateJWT(user: User): { access_token: string } {
        const payload: PayloadToken = {
            role: user.role,
            sub: (user._id as Types.ObjectId).toString(),
        };

        return {
            access_token: this.jwtService.sign(payload),
        };
    }

    async register(createUserDto: CreateUserDto): Promise<User> {
        const { email } = createUserDto;

        const existingUser = await this.userModel.findOne({ email });
        if (existingUser) {
            throw new ConflictException('El correo electrónico ya está registrado');
        }

        const user = new this.userModel(createUserDto);
        await user.hashPassword();
        await user.save();

        return user;
    }

    async validateGoogleUser(googleUser: any): Promise<{ user: User; token: { access_token: string } }> {
        try {
            const email = googleUser.email;
            let user = await this.userModel.findOne({ email });

            if (!user) {
                const newUser = {
                    email: googleUser.email,
                    fullname: `${googleUser.firstName || ''} ${googleUser.lastName || ''}`.trim(),
                    birthdate: new Date(),
                    password: Math.random().toString(36).slice(-8),
                    role: UserRole.USER
                };

                user = new this.userModel(newUser);
                await user.hashPassword();
                await user.save();
            }

            const token = this.generateJWT(user);
            return { user, token };
        } catch (error) {
            console.error('Error in validateGoogleUser:', error);
            throw error;
        }
    }
} 
