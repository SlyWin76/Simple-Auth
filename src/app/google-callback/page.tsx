"use client";

import { useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { loginOrRegisterWithGoogleCode, checkUserByGoogleId, getGoogleUserInfo, getGoogleAccessToken } from "../actions";
import Link from "next/link";


export default function GoogleCallback() {
    const SearchParams = useSearchParams();
    const code = SearchParams.get("code");

    const [error, setError] = useState<string | null>(null);


    const processGoogleCode = async () => {
        if(!code) {
            setError("No code found in URL params");
            return;
        }

        const accessToken = await getGoogleAccessToken(code);
        if (!accessToken) {
          setError('Erreur lors de la récupération du access_token');
          return;
        }
  
        const userInfo = await getGoogleUserInfo(accessToken);
        if (!userInfo) {
          setError('Erreur lors de la récupération des informations de l\'utilisateur Google');
          return;
        }
  
        const userExists = await checkUserByGoogleId(userInfo.googleId);

        const success = await loginOrRegisterWithGoogleCode(code);
        if (!success) {
            setError("An error occured during processs");
        }
    };

    useEffect(() => {
        processGoogleCode();
    }, [code]);


    return (
        <div className="flex justify-center items-center">
            {error && (
                <div className="flex justify-center items-center">
                    <div className="text-blue-500 text-lg">
                        {error}
                    </div>
                    <Link href="/" className="text-sm bg-gray-300 px-3 py-2 hover:bg-gray-400">back to home</Link>
                </div>
            )}
        </div>
    );
}