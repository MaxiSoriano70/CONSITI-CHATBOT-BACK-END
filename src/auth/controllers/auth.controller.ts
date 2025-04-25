import {
    Body,
    Controller,
    Get,
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
import { GoogleAuthGuard } from '../guards/google-auth.guard';
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

    @Get('google/login')
    @UseGuards(GoogleAuthGuard)
    googleLogin() {
    }

    @Get('google/callback')
    @UseGuards(GoogleAuthGuard)
    async googleCallback(@Req() req: Request) {
        const googleUser = req.user;
        if (!googleUser) {
            throw new UnauthorizedException('Fallo al autenticar con Google');
        }
        const { user, token } = await this.authService.validateGoogleUser(googleUser);
        const userResponse = toUserResponse(user);
        return {
            user: userResponse,
            ...token,
        };
    }
}