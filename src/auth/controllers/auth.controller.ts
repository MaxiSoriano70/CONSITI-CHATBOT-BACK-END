import {
    Body,
    Controller,
    Post,
    Req,
    UnauthorizedException,
    UseGuards,
    ValidationPipe, } from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from '../services/auth.service';
import { AuthGuard } from '@nestjs/passport';
import { CreateUserDto } from '../dtos/create-user.dto';
import { toUserResponse } from '../dtos/user-response.dto';
import { User } from '../models/user.schema';
@Controller('auth')
export class AuthController {
constructor(private authService: AuthService) {}

@UseGuards(AuthGuard('local'))
@Post('login')
@UseGuards(AuthGuard('local'))
async login(@Req() req: Request) {
    const user = req.user;

    if (!user) {
        throw new UnauthorizedException('Usuario no autenticado');
    }

    const token = this.authService.generateJWT(user as User);
    const userResponse = toUserResponse(user);
    return {
        user: userResponse,
        ...token,
    };
}


@Post('register')
async register(@Body(new ValidationPipe({ whitelist: true })) createUserDto: CreateUserDto,){
    const newUser = await this.authService.register(createUserDto);
    const token = this.authService.generateJWT(newUser);
    const userResponse = toUserResponse(newUser);
    return {
    user: userResponse,
    ...token,};
    }
}