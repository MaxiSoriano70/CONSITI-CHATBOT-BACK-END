import { Injectable, ConflictException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { User } from '../models/user.schema';
import { PayloadToken } from '../models/token.model';
import * as bcrypt from 'bcrypt';
import { CreateUserDto } from '../dtos/create-user.dto';
import { hashPassword } from '../utils/hash-password.util';
import { UserRole } from '../enums/user-role.enum';
import { EmailService } from './email.service';


@Injectable()
export class AuthService {
    constructor(
        private jwtService: JwtService,
        @InjectModel(User.name) private userModel: Model<User>,
        private emailService: EmailService,
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
        const { email, password, birthdate } = createUserDto;
        if (!password) {
            throw new ConflictException('La contraseña es obligatoria para el registro.');
        }

        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$/;
        if (!passwordRegex.test(password)) {
            throw new BadRequestException(
                'La contraseña debe tener al menos 6 caracteres, una mayúscula, una minúscula y un número.'
            );
        }

        if (!birthdate) {
            throw new ConflictException('La fecha de nacimiento es obligatoria para el registro.');
        }

        const birthdateObj = new Date(birthdate);
        const today = new Date();

        if (birthdateObj > today) {
            throw new BadRequestException('La fecha de nacimiento no puede ser mayor a hoy.');
        }

        const existingUser = await this.userModel.findOne({ email });
        if (existingUser) {
            throw new ConflictException('El correo electrónico ya está registrado.');
        }

        const user = new this.userModel(createUserDto);
        await user.save();
        return user;
    }

    async loginWithGoogle(googleUser: any): Promise<{ user: User; token: { access_token: string } }> {
        const email = googleUser.email;
        const user = await this.userModel.findOne({ email });

        if (!user) {
            throw new ConflictException('Este usuario no está registrado. Regístrate primero con Google.');
        }

        const token = this.generateJWT(user);
        return { user, token };
    }

    async registerWithGoogle(googleUser: any): Promise<{ user: User; token: { access_token: string } }> {
        const email = googleUser.email;
        let user = await this.userModel.findOne({ email });
        if (user) {
            throw new ConflictException('Este usuario ya está registrado. Inicia sesión con Google.');
        }
        const newUser = new this.userModel({
            email: googleUser.email,
            fullname: `${googleUser.firstName || ''} ${googleUser.lastName || ''}`.trim(),
            role: UserRole.USER,
            password: null,
            birthdate: null,
        });
        await newUser.save();
        const token = this.generateJWT(newUser);
        return { user: newUser, token };
    }

    async requestPasswordReset(email: string): Promise<void> {
        const user = await this.userModel.findOne({ email });
        if (!user) throw new BadRequestException('No se encontró un usuario con ese correo.');

        const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiration = new Date(Date.now() + 15 * 60 * 1000);

        user.resetCode = resetCode;
        user.resetCodeExpiration = expiration;
        await user.save();

        await this.emailService.sendResetEmail(user.email, resetCode);
    }

    async confirmPasswordReset(email: string, code: string, newPassword: string): Promise<void> {
        const user = await this.userModel.findOne({ email });

        if (!user || user.resetCode !== code) {
            throw new BadRequestException('Código inválido o usuario no encontrado.');
        }

        if (!user.resetCodeExpiration || user.resetCodeExpiration < new Date()) {
            throw new BadRequestException('El código ha expirado.');
        }

        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$/;
        if (!passwordRegex.test(newPassword)) {
            throw new BadRequestException('Contraseña no cumple con los requisitos.');
        }

        user.password = newPassword;
        user.resetCode = undefined;
        user.resetCodeExpiration = undefined;
        await user.save();
    }

}