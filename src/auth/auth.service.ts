import { ForbiddenException, Injectable } from '@nestjs/common';
import { AuthDto } from './dto';
import { DbService } from '../db/db.service';
import * as argon from 'argon2';
import { async } from 'rxjs';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable({})
export class AuthService {
  constructor(private db: DbService) {}
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
    // Return the user
    return user;
  }
}
