"use server";

import { cookies } from "next/headers";
import * as jose from "jose";
import User, { UserDocument } from "@/models/User";
import connect from "@/utils/db";
import { redirect } from "next/navigation";
import bcrypt from "bcryptjs"
import { SignJWT } from "jose";
import { createSecretKey } from "crypto";

//redirection
export const SignInWithProvider = () => {
  redirect(`https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=434602169782-t30f4445vjc522c8aip2mn607nm9q84e.apps.googleusercontent.com&redirect_uri=http://localhost:3000/google-callback&scope=email%20profile&state=someStateValue&prompt=consent`);
};

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
    const user = await User.findOne({ _id: userId }, { _id: 1, email: 1 });
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

//Login avec email et mdp
export const loginUserWithEmailAndPassword = async (email: string, password: string): Promise<UserDocument | null> => {
  try {
    const user: UserDocument | null = await User.findOne({ email });

    if (!user) {
      return null;
    }

    if (user.googleId) {
      return null;
    }

    const passwordMatch = await bcrypt.compare(password, user.password || '');

    if (passwordMatch) {
      return user;
    } else {
      return null;
    }
  } catch (error) {
    console.error('Erreur lors de l\'authentification avec mot de passe:', error);
    return null;
  }
};

//Inscription avec email et mdp
export const createUserWithEmailAndPassword = async (email: string, password: string): Promise<UserDocument | null> => {
  try {
    const existingUser: UserDocument | null = await User.findOne({ email });

    if (existingUser) {
      // Un utilisateur avec cet e-mail existe déjà
      return null;
    }

    // Hacher le mot de passe avant de l'enregistrer
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      email,
      password: hashedPassword,
    });

    const savedUser = await newUser.save();

    return savedUser;
  } catch (error) {
    console.error('Erreur lors de la création de l\'utilisateur avec mot de passe:', error);
    return null;
  }
};





//OAuth 2.0<

export const loginOrRegisterWithGoogleCode = async (code: string): Promise<string | null> => {

  let user: UserDocument | null = null;
  
  try {
    const accessToken = await getGoogleAccessToken(code);
    if (!accessToken) {
      return null;
    }

    const userInfo = await getGoogleUserInfo(accessToken);
    if (!userInfo) {
      return null;
    }

    const userExists = await checkUserByGoogleId(userInfo.googleId);

    if (!userExists) {
      user = await createUserWithGoogleInfo(userInfo);
    } else {
      user = await getUserByGoogleId(userInfo.googleId);
    }

    if (!user) {
      return null;
    }
    
    const token = generateJWTToken(user);

    return token;
  } catch (error) {
    console.error('Erreur lors de la connexion/inscription avec Google:', error);
    return null;
  }
};


//Récupérer le token d'accès
export const getGoogleAccessToken = async (code: string): Promise<string | null> => {
  const googleTokenEndpoint = 'https://oauth2.googleapis.com/token';
  const clientId = process.env.GOOGLE_CLIENT_ID || "";
  const clientSecret = process.env.GOOGLE_SECRET || "";
  const redirectUri = process.env.NEXT_URL || "";

  try {
    const response = await fetch(googleTokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: '${redirectUri}/google-callback',
        grant_type: 'authorization_code',
      }),
    });

    const data = await response.json();

    if (response.ok) {
      return data.access_token;
    } else {
      console.log('Erreur lors de la récupération du access_token:', data.error);
      return null;
    }
  } catch (error) {
    console.error('Erreur réseau lors de la récupération du access_token:', error);
    return null;
  }
};


//récupérer les données de l'utilisateur
export const getGoogleUserInfo = async (accessToken: string): Promise<{ email: string; googleId: string } | null> => {
  const googleUserInfoEndpoint = 'https://www.googleapis.com/oauth2/v1/userinfo';

  try {
    const response = await fetch(googleUserInfoEndpoint, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    const data = await response.json();

    if (response.ok) {
      return {
        email: data.email,
        googleId: data.id,
      };
    } else {
      console.error('Erreur lors de la récupération des informations de l\'utilisateur Google:', data.error);
      return null;
    }
  } catch (error) {
    console.error('Erreur réseau lors de la récupération des informations de l\'utilisateur Google:', error);
    return null;
  }
};

export const checkUserByGoogleId = async (googleId: string): Promise<boolean> => {
  try {
    const user: UserDocument | null = await User.findOne({ googleId });

    return !!user;
  } catch (error) {
    console.error('Erreur lors de la vérification de l\'utilisateur par googleId:', error);
    return false;
  }
};

const createUserWithGoogleInfo = async (userInfo: { email: string; googleId: string }): Promise<UserDocument | null> => {
  try {
    const newUser = new User({
      email: userInfo.email,
      googleId: userInfo.googleId,
    });

    const savedUser = await newUser.save();
    return savedUser;
  } catch (error) {
    console.error('Erreur lors de la création de l\'utilisateur avec GoogleInfo:', error);
    return null;
  }
};

const getUserByGoogleId = async (googleId: string): Promise<UserDocument | null> => {
  try {
    const user: UserDocument | null = await User.findOne({ googleId });
    return user;
  } catch (error) {
    console.error('Erreur lors de la récupération de l\'utilisateur par GoogleId:', error);
    return null;
  }
};


const generateJWTToken = async (user: UserDocument): Promise<string> => {
  try {
    const key = createSecretKey(Buffer.from(process.env.JWT_SECRET || '', 'base64'));
    
    const jwt = await new SignJWT({ userId: user._id, email: user.email })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(key);

    // Placez le token dans les cookies ici (vous devrez envoyer le token au client et le stocker dans les cookies côté client)
    // Vous devrez implémenter une fonction appropriée pour gérer les cookies côté serveur

    return jwt;
  } catch (error) {
    console.error('Erreur lors de la génération du token JWT:', error);
    throw error;
  }
};
