import { Request } from 'express';
import session from 'express-session';
import { ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

export interface SessionRequest extends Request {
    session: session.Session & Partial<session.SessionData> & {
        state?: string;
    };
}

@Injectable()
export class GoogleAuthGuard extends AuthGuard('google') {
    getAuthenticateOptions(context: ExecutionContext): any {
        const request = context.switchToHttp().getRequest<SessionRequest>();
        let state: string | undefined;

        if (request.path.includes('login')) {
        state = 'login';
        } else if (request.path.includes('register')) {
        state = 'register';
        }
        return { state };
    }
}
