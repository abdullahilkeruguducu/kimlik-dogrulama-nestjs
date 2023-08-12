import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signup(dto: AuthDto) {
    if (!dto.email || !dto.password) {
      throw new BadRequestException('Email and password cannot be empty');
    }

    const hash = await argon.hash(dto.password);
    try {
      if (dto.role && !['user', 'admin'].includes(dto.role)) {
        throw new BadRequestException(
          'Invalid role. Allowed values: user, admin',
        );
      }
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
          role: dto.role || 'user',
        },
      });
      delete user.hash;

      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        throw new ForbiddenException('User Exist!');
      }
      throw error;
    }
  }

  async signin(dto: AuthDto) {
    if (!dto.email || !dto.password) {
      throw new BadRequestException('Email and password cannot be empty');
    }

    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) throw new ForbiddenException('User not found!');

    const pwMatches = await argon.verify(user.hash, dto.password);

    if (!pwMatches) throw new ForbiddenException('Credentials incorrect');

    const token = await this.signToken(user.id, user.email);

    return { user, token };
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };
    const secret = this.config.get('JWT_SECRET');

    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: secret,
    });
    return { access_token: token };
  }
}
