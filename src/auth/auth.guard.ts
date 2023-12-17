import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User, Role } from '@prisma/client';
import { Request } from 'express';
interface AuthenticatedRequest extends Request {
  user: User & { role: Role & { permissions: Array<string> } };
}

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const token = this.extractTokenFromHeader(request);
    // If there is not token
    if (!token) throw new UnauthorizedException('Token is missing');

    try {
      // Token payload
      const payload = await this.jwtService.verifyAsync(token, {
        secret: process.env.JWT_SECRET,
      });

      // Storing the payload in the request
      request['user'] = payload;
    } catch {
      // If there is something wrong with the token
      throw new UnauthorizedException('Token malformed');
    }
    return true;
  }

  /**
   * We extract the token from the header Authorization
   * @param request
   * @returns
   */
  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
