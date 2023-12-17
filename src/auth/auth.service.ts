/* eslint-disable @typescript-eslint/no-unused-vars */
import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { LoginDto } from './dto/login.dto';
import { BcriptService } from 'src/bcript/bcript.service';
import { JwtService } from '@nestjs/jwt';
import { RegisterDto } from './dto/register.dto';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private bcript: BcriptService,
    private jwtService: JwtService,
  ) {}

  /**
   *
   * @param {LoginDto} dtoLogin
   * @returns
   */
  async signin(dtoLogin: LoginDto) {
    const { email } = dtoLogin;

    // Query
    const user = await this.prisma.user.findFirst({
      where: {
        email,
      },
      select: {
        id: true,
        email: true,
        name: true,
        roleId: true,
        state: true,
        password: true,
        role: {
          select: {
            id: true,
            name: true,
            rolePermission: {
              select: {
                permission: {
                  select: {
                    code: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    // If not exits
    if (!user) throw new UnauthorizedException();

    // If is banned
    if (!user.state) throw new UnauthorizedException('Deshabilitado');

    // If password match
    const isEqual = await this.bcript.compare(dtoLogin.password, user.password);
    if (!isEqual)
      throw new UnauthorizedException('Contraseña o Email incorrectos');

    // Destructuring
    const {
      password,
      role: { rolePermission, ...roleRest },
      ...rest
    } = user;

    // Creating an array of permissions <string>
    const permissions = user.role.rolePermission.map(
      ({ permission: { code } }) => code,
    );

    // Creating a new object
    const newUser = {
      ...rest,
      role: {
        ...roleRest,
        permissions,
      },
    };

    // Generating and return a token and user
    return {
      token: await this.jwtService.signAsync(
        { id: newUser.id },
        {
          secret: process.env.JWT_SECRET,
        },
      ),
      user: newUser,
    };
  }

  /**
   * @param {RegisterDto} dtoRegister
   * @returns
   */
  async signup(dtoRegister: RegisterDto) {
    // Query
    const encryptPassword = await this.bcript.encrypt(dtoRegister.password);
    try {
      const user = await this.prisma.user.create({
        data: {
          ...dtoRegister,
          password: encryptPassword,
        },
        select: {
          id: true,
          email: true,
          name: true,
          roleId: true,
          state: true,
          password: true,
          role: {
            select: {
              id: true,
              name: true,
              rolePermission: {
                select: {
                  permission: {
                    select: {
                      code: true,
                    },
                  },
                },
              },
            },
          },
        },
      });
      const {
        password,
        role: { rolePermission, ...roleRest },
        ...rest
      } = user;

      // Creating an array of permissions <string>
      const permissions = user.role.rolePermission.map(
        ({ permission: { code } }) => code,
      );

      // Creating a new object
      const newUser = {
        ...rest,
        role: {
          ...roleRest,
          permissions,
        },
      };

      // Generating and return a token and user
      return {
        token: await this.jwtService.signAsync(
          { id: newUser.id },
          {
            secret: process.env.JWT_SECRET,
          },
        ),
        user: newUser,
      };
    } catch (error) {
      if (error.code === 'P2002')
        throw new BadRequestException('Ese correo ya está registrado');

      throw new InternalServerErrorException(error.message);
    }
  }

  /**
   * @param {id} string
   * @returns
   */
  async profile(id: string) {
    const user = await this.prisma.user.findUnique({
      where: {
        id,
      },
      select: {
        id: true,
        email: true,
        name: true,
        roleId: true,
        state: true,
        role: {
          select: {
            id: true,
            name: true,
            rolePermission: {
              select: {
                permission: {
                  select: {
                    code: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    if (!user) return undefined;

    const permissions = user.role.rolePermission.map(
      ({ permission: { code } }) => code,
    );

    const {
      role: { rolePermission, ...roleRest },
      ...rest
    } = user;

    const newUser = {
      ...rest,
      role: {
        ...roleRest,
        permissions,
      },
    };

    return newUser;
  }
}
