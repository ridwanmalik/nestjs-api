import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { User } from '@prisma/client';
import { Request } from 'express';
import { GetUser } from 'src/auth/decorator';
import { jwtGuard } from 'src/auth/guard/jwt.guard';

@Controller('users')
export class UserController {
  @UseGuards(jwtGuard)
  @Get('me')
  async getMe(@GetUser() user: User) {
    return user;
  }
}
