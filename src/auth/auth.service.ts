import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(dto: AuthDto) {
    const hash = await argon.hash(dto.password);

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
  }

  async signin(dto: AuthDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) throw new ForbiddenException('User not found!');

    const pwMatches = await argon.verify(user.hash, dto.password);

    if (!pwMatches) throw new ForbiddenException('Credentials incorrect');

    return user;
  }
}
