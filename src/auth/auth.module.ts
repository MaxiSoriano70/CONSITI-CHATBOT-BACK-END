import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthService } from './services/auth.service';
import { AuthController } from './controllers/auth.controller';
import { LocalStrategy } from './strategies/local.strategy';
import { User, UserSchema } from './models/user.schema';
import { GoogleStrategy } from './strategies/google.strategy';
import { EmailService } from './services/email.service';

@Module({
  imports: [
    PassportModule,
    JwtModule.registerAsync({
      useFactory: () => ({
        secret: 'CHATBOT!@#',
        signOptions: { expiresIn: '1d' },
      }),
    }),
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema }
    ]),
  ],
  providers: [
    AuthService,
    LocalStrategy,
    GoogleStrategy,
    EmailService,
  ],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}
