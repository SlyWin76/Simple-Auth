"use client";

import { useRouter } from "next/navigation";
import {
  deleteAuthCookie,
  disableTotpForLoggedUser,
  getLoggedUserDocument,
} from "./actions";
import { useEffect, useState } from "react";
import Link from "next/link";
import { UserDocument } from "@/models/User";

export default function Home() {
  const router = useRouter();

  const [user, setUser] = useState<UserDocument | null>(null);
  const [error, setError] = useState<string | null>(null);

  const getLoggedUserInfos = async () => {
    const user = await getLoggedUserDocument();
    if (!user) {
      setError("Error while accessing user infos");
      return;
    }
    setUser(user);
  };

  useEffect(() => {
    getLoggedUserInfos();
  }, []);

  const logout = () => {
    deleteAuthCookie();
  };

  const disableTotp = async () => {
    const isTotpDisabled = await disableTotpForLoggedUser();
    if (!isTotpDisabled) {
      setError("Error while disabling TOTP");
      return;
    }
    getLoggedUserInfos();
  };

  return (
    <div className="h-screen flex flex-col justify-center items-center">
      <h1 className="text-4xl font-bold">You are connected.</h1>
      {user && <h2 className="text-2xl mt-3">{user.email}</h2>}

      <button
        onClick={() => logout()}
        className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded cursor-pointer mt-5"
      >
        Logout
      </button>

      {user && user.totpSecret !== null ? (
        <button
          onClick={() => disableTotp()}
          className="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded cursor-pointer mt-3"
        >
          Disable TOTP
        </button>
      ) : (
        <Link
          href="/init-totp"
          className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded cursor-pointer mt-3"
        >
          Enable TOTP
        </Link>
      )}

      {error && <p className="text-red-500 mt-3">{error}</p>}
    </div>
  );
}
