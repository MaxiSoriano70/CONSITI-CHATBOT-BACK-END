// src/auth/dto/create-user.dto.ts
import { IsEmail, IsNotEmpty, MinLength, IsDateString } from 'class-validator';
import { UserRole } from '../enums/user-role.enum';

export class CreateUserDto {
    @IsEmail()
    @IsNotEmpty()
    email: string;

    @IsNotEmpty()
    @MinLength(3)
    fullname: string;

    @IsNotEmpty()
    @IsDateString()
    birthdate: string;

    @IsNotEmpty()
    @MinLength(6)
    password: string;

    role?: UserRole;
}
