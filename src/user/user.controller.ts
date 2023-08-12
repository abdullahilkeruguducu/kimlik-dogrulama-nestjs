import { Body, Controller, Get, UseGuards } from '@nestjs/common';
import { User } from '@prisma/client';
import { JwtGuard } from '../auth/guard';
import { GetUser } from 'src/auth/decorator';

@UseGuards(JwtGuard)
@Controller('users')
export class UserController {
  @Get('user')
  getUser(@GetUser() user: User) {
    return user;
  }

  @Get('admin')
  getAdmin(@GetUser() user: User) {
    if (user.role === 'admin') {
      return user;
    }
    return 'This is an admin endpoint';
  }
}
