// /api/login/route.ts

import User from "@/models/User";
import connect from "@/utils/db";
import bcrypt from "bcryptjs";
import { NextResponse } from "next/server";
import * as jose from "jose";
import { authenticator } from "otplib";

export const POST = async (request: any) => {
  const { email, password, totpCode } = await request.json();

  await connect();

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return NextResponse.json(
        { errorString: "User with this email not found", totpRequired: false },
        {
          status: 401,
        }
      );
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return NextResponse.json(
        { errorString: "Invalid password", totpRequired: false },
        {
          status: 401,
        }
      );
    }

    if (user.totpSecret !== null) {
      if (!totpCode) {
        return NextResponse.json(
          { errorString: "TOTP code is required", totpRequired: true },
          {
            status: 401,
          }
        );
      }

      const isValid = await authenticator.verify({
        token: totpCode,
        secret: user.totpSecret,
      });
      if (!isValid) {
        return NextResponse.json(
          { errorString: "Invalid TOTP code", totpRequired: true },
          { status: 401 }
        );
      }
    }

    const secret = new TextEncoder().encode(process.env.JWT_SECRET || "");
    const token = await new jose.SignJWT({
      uid: user._id,
      totpEnabled: user.totpEnabled,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime("4h")
      .sign(secret);

    return NextResponse.json({ token }, { status: 200 });
  } catch (err: any) {
    return new NextResponse(err, {
      status: 500,
    });
  }
};
