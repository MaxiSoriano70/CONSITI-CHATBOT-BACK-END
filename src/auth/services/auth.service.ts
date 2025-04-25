import { Injectable, ConflictException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { User } from '../models/user.schema';
import { PayloadToken } from '../models/token.model';
import * as bcrypt from 'bcrypt';
import { CreateUserDto } from '../dtos/create-user.dto';
import { hashPassword } from '../utils/hash-password.util';

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
        const { email, password } = createUserDto;
        const existingUser = await this.userModel.findOne({ email });
        if (existingUser) {
            throw new ConflictException('El correo electrónico ya está registrado');
        }

        const hashedPassword = await hashPassword(password);

        const user = await this.userModel.create({ ...createUserDto, password: hashedPassword });
        await user.save();
        return user;
    }
}