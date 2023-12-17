import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { User, Role } from '@prisma/client';

interface AuthenticatedRequest extends Request {
  user: User & { role: Role & { permissions: Array<string> } };
}

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.get<string[]>(
      'roles',
      context.getHandler(),
    );
    if (!requiredRoles) return true;

    const user = context.switchToHttp().getRequest<AuthenticatedRequest>().user;
    return requiredRoles.some((role) => user.role.permissions.includes(role));
  }
}
