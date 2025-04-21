import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User } from "../models/user.model";
import { PayloadToken } from '../models/token.model';

@Injectable()
export class AuthService {
    constructor(private jwtService: JwtService){
    }

    async validateUser(email: string, password: string){
        const users: User[] = [
            {
                email: "maxi@gmail.com",
                password: "maxi123",
                role: "ADMIN",
                id: 1
            }
        ];

        const user = users.find(
            (x: User) => x.email === email && x.password === password
        );

        if(user){
            return user;
        }

        return null;
    }

    generateJWT(user: User){
        const payload: PayloadToken = { role: user.role, sub:user.id};
        return{
            access_token: this.jwtService.sign(payload),
        };
    }
}
