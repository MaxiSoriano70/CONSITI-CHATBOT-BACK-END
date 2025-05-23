import {
    BadRequestException,
    Body,
    Controller,
    Get,
    Post,
    Req,
    Res,
    UnauthorizedException,
    UseGuards,
    ValidationPipe,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthService } from '../services/auth.service';
import { AuthGuard } from '@nestjs/passport';
import { CreateUserDto } from '../dtos/create-user.dto';
import { toUserResponse } from '../dtos/user-response.dto';
import { User } from '../models/user.schema';
import { GoogleAuthGuard } from '../guards/google-auth.guard';
import session from 'express-session';
import { RequestPasswordResetDto } from '../dtos/password-reset-request.dto';
import { ConfirmPasswordResetDto } from '../dtos/confirm-password-reset.dto';
import { ChecketCodeDto } from '../dtos/checket-code.dto';
interface SessionRequest extends Request {
    session: session.Session & Partial<session.SessionData> & { state?: string };
}

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    @UseGuards(AuthGuard('local'))
    @Post('login')
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
    async register(
        @Body(new ValidationPipe({ whitelist: true })) createUserDto: CreateUserDto,
    ) {
        const newUser = await this.authService.register(createUserDto);
        const token = this.authService.generateJWT(newUser);
        const userResponse = toUserResponse(newUser);
        return {
            user: userResponse,
            ...token,
        };
    }

    @Get('google/login')
    async googleLogin(@Req() req: SessionRequest, @Res() res: Response) {
        req.session.state = 'login';
        console.log('Estado asignado para Google Login:', req.session.state);
        return res.redirect('/auth/google');
    }

    @Get('google/register')
    async googleRegister(@Req() req: SessionRequest, @Res() res: Response) {
        req.session.state = 'register';
        console.log('Estado asignado para Google Register:', req.session.state);
        return res.redirect('/auth/google');
    }

    @Get('google')
    @UseGuards(GoogleAuthGuard)
    googleAuth() {
    }

    @Get('google/callback')
    @UseGuards(GoogleAuthGuard)
    async googleCallback(@Req() req: SessionRequest) {
        const googleUser = req.user;
        const state = req.session.state;
        console.log('Estado en callback:', state);
        if (!googleUser) {
        throw new UnauthorizedException('Fallo al autenticar con Google.');
        }
        if (state === 'login') {
        const { user, token } = await this.authService.loginWithGoogle(googleUser);
        return { user: toUserResponse(user), ...token };
        } else if (state === 'register') {
        const { user, token } = await this.authService.registerWithGoogle(googleUser);
        return { user: toUserResponse(user), ...token };
        } else {
        throw new BadRequestException('Estado de autenticación desconocido.');
        }
    }

    @Post('password-reset/request')
    async requestPasswordReset(
        @Body(new ValidationPipe({ whitelist: true })) dto: RequestPasswordResetDto,
    ) {
        await this.authService.requestPasswordReset(dto.email);
        return { message: 'Se ha enviado un código de recuperación al correo electrónico' };
    }

    @Post('password-reset/check-code')
    async checkResetCode(@Body(new ValidationPipe({ whitelist: true })) dto: ChecketCodeDto) {
        const isValid = await this.authService.verifyResetCode(dto.email, dto.code);
    if (!isValid) {
        throw new BadRequestException('Código inválido o expirado.');
    }
        return { message: 'Código válido. Puedes continuar con el cambio de contraseña.' };
    }

    @Post('password-reset/confirm')
    async confirmPasswordReset(@Body(new ValidationPipe({ whitelist: true })) dto: ConfirmPasswordResetDto) {
        await this.authService.confirmPasswordReset(dto.email, dto.code, dto.newPassword);
        return { message: 'Contraseña actualizada exitosamente' };
    }

}
