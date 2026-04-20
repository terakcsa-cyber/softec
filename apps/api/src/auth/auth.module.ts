import { Module } from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";
import { PassportModule } from "@nestjs/passport";
import { AuthController } from "./auth.controller.js";
import { AuthService } from "./auth.service.js";
import { JwtStrategy } from "./jwt.strategy.js";

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: "jwt" }),
    JwtModule.registerAsync({
      useFactory: () => {
        const secret = process.env.JWT_SECRET?.trim();
        if (!secret || secret.length < 32) {
          throw new Error("JWT_SECRET must be set and at least 32 characters");
        }
        return {
          secret,
          signOptions: { expiresIn: "15m" }
        };
      }
    })
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
  exports: [AuthService]
})
export class AuthModule {}
