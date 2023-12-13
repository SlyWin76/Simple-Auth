"use server";

import { cookies } from "next/headers";
import * as jose from "jose";
import { authenticator } from "otplib";
import { toDataURL } from "qrcode";
import User, { UserDocument } from "@/models/User";
import connect from "@/utils/db";
import { redirect } from "next/navigation";

export const setAuthCookie = (token: string): void => {
  cookies().set("authToken", token);
  redirect("/");
};

export const deleteAuthCookie = (): void => {
  cookies().delete("authToken");
  redirect("/login");
};

export const extractJwtTokenFromCookie = (): string | null => {
  const cookieStore = cookies();
  const cookie = cookieStore.get("authToken");
  const jwt = cookie?.value;
  return jwt || null;
};

export const extractUserIdFromJwt = async (
  jwt: string
): Promise<string | null> => {
  const secret = new TextEncoder().encode(process.env.JWT_SECRET || "");
  try {
    const { payload } = await jose.jwtVerify(jwt, secret);
    return payload.uid as string;
  } catch (err: any) {
    console.error(err);
    return null;
  }
};

export const getUserDocumentFromUserId = async (
  userId: string
): Promise<UserDocument | null> => {
  await connect();
  try {
    const user = await User.findOne(
      { _id: userId },
      { _id: 1, email: 1, totpSecret: 1 }
    );
    return JSON.parse(JSON.stringify(user)); // This weird thing is here to be sure user is a json object and not a mongoose document
  } catch (err: any) {
    console.error(err);
    return null;
  }
};

export const getLoggedUserId = async (): Promise<string | null> => {
  const jwt = extractJwtTokenFromCookie();
  if (!jwt) return null;
  const userId = await extractUserIdFromJwt(jwt);
  return userId;
};

export const getLoggedUserDocument = async (): Promise<UserDocument | null> => {
  const userId = await getLoggedUserId();
  if (!userId) return null;
  const user = await getUserDocumentFromUserId(userId);
  return user;
};

export const generateTotpSecretAndQrcodeForLoggedUser = async (): Promise<{
  base32Secret: string;
  base64Qrcode: string;
} | null> => {
  const user = await getLoggedUserDocument();
  if (!user) return null;
  const base32Secret = authenticator.generateSecret();
  const registrationUri = authenticator.keyuri(
    user.email,
    "simple-auth-nextjs",
    base32Secret
  );
  const base64Qrcode = await toDataURL(registrationUri);
  return {
    base32Secret,
    base64Qrcode,
  };
};

export const isTotpCodeValid = async (
  sixDigitCode: string,
  base32Secret: string
): Promise<boolean> => {
  const isValid = await authenticator.verify({
    token: sixDigitCode,
    secret: base32Secret,
  });
  return isValid;
};

export const enableTotpForLoggedUser = async (
  base32Secret: string
): Promise<boolean> => {
  const userId = await getLoggedUserId();
  if (!userId) return false;
  await connect();
  try {
    let user = await User.findOne({ _id: userId });
    user.totpSecret = base32Secret;
    await user.save();
    return true;
  } catch (err: any) {
    console.error(err);
    return false;
  }
};

export const disableTotpForLoggedUser = async (): Promise<boolean> => {
  const userId = await getLoggedUserId();
  await connect();
  try {
    let user = await User.findOne({ _id: userId });
    user.totpSecret = null;
    await user.save();
    return true;
  } catch (err: any) {
    console.error(err);
    return false;
  }
};
