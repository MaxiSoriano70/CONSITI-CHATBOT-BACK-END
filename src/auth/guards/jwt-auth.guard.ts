import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { Observable } from 'rxjs';
import { IS_PUBLIC_KEY } from '../decorator/public.decorator';

@Injectable()
export class JwtAuthGuard extends AuthGuard("jwt") {
    constructor(private reflector: Reflector){
      super();
    }

    canActivate(context: ExecutionContext){
      const isPublic = this.reflector.get(IS_PUBLIC_KEY, context.getHandler());
      if(isPublic){
        return true;
      }
      return super.canActivate(context);
    }
}
