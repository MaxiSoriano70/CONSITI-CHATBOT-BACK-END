import { PassportStrategy } from "@nestjs/passport";
import { Strategy } from "passport-local";
import { AuthService } from "../services/auth.service";
import { Injectable, UnauthorizedException } from "@nestjs/common";
import { User } from "../models/user.schema";

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy, "local") {
    constructor(private authService: AuthService) {
        super({
            usernameField: "email",
            passwordField: "password"
        });
    }

    async validate(email: string, password: string): Promise<User> {
        const user = await this.authService.validateUser(email, password);
        if (!user) {
            throw new UnauthorizedException("Not Allowed");
        }
        return user;
    }
}
