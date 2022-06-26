import { ForbiddenException, Injectable } from '@nestjs/common';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';

import { DbService } from '../db/db.service';
import { AuthDto } from './dto';
import { ConfigService } from '@nestjs/config';

@Injectable({})
export class AuthService {
  constructor(
    private db: DbService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async signup(dto: AuthDto) {
    // Generate the password
    const hash = await argon.hash(dto.password);
    try {
      // Save the new user to the db
      const user = await this.db.user.create({
        data: {
          email: dto.email,
          password: hash,
        },
      });
      // Delete hidden properties form the user
      delete user.password;
      // return the saved user
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code == 'P2002')
          throw new ForbiddenException('Email Already in Use');
      }
    }
  }

  async signin(dto: AuthDto) {
    // Find the user by email
    const user = await this.db.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    // If user dose not exist throw exception
    if (!user) throw new ForbiddenException('Credentials incorrect');
    // Compare password
    const passwordMatch = await argon.verify(user.password, dto.password);
    // If password incorrect throw exception
    if (!passwordMatch) throw new ForbiddenException('Credentials incorrect');
    // Delete hidden properties form the user
    delete user.password;
    // Return the user with token
    return {
      access_token: this.signToken(user.id, user.email),
      user,
    };
  }

  signToken(userId: number, email: string): Promise<string> {
    const payload = {
      sub: userId,
      email,
    };

    const secret = this.config.get('JWT_SECRET');

    return this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret,
    });
  }
}
