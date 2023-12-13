/* eslint-disable @next/next/no-img-element */
"use client";

import { useEffect, useState } from "react";
import {
  isTotpCodeValid,
  enableTotpForLoggedUser,
  generateTotpSecretAndQrcodeForLoggedUser,
} from "../actions";
import { useRouter } from "next/navigation";

export default function InitTotp() {
  const router = useRouter();

  const [code, setCode] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [totpSecretAndQrcode, setTotpSecretAndQrcode] = useState<{
    base32Secret: string;
    base64Qrcode: string;
  } | null>(null);

  const inititializeNewTotp = async () => {
    const newTotpSecretAndQrcode =
      await generateTotpSecretAndQrcodeForLoggedUser();
    setTotpSecretAndQrcode(newTotpSecretAndQrcode);
  };

  useEffect(() => {
    inititializeNewTotp();
  }, []);

  const submitCode = async () => {
    setError(null);

    if (code.length !== 6) {
      setError("Invalid code (must be 6 digits)");
      return;
    }
    if (!/^\d+$/.test(code)) {
      setError("Invalid code (must be numeric)");
      return;
    }
    if (!totpSecretAndQrcode) {
      setError("Error while generating TOTP secret");
      return;
    }

    const isValid = await isTotpCodeValid(code, totpSecretAndQrcode.base32Secret);
    if (!isValid) {
      setError("Invalid code");
      return;
    }
    
    const isEnabled = await enableTotpForLoggedUser(totpSecretAndQrcode.base32Secret);
    if (!isEnabled) {
      setError("Error while enabling TOTP");
      return;
    }
    
    router.push("/");
  };

  return (
    <div className="flex flex-col justify-center items-center h-screen">
      {totpSecretAndQrcode && totpSecretAndQrcode.base64Qrcode && (
        <>
          <img src={totpSecretAndQrcode.base64Qrcode} alt="TOTP QR Code" />
          <input
            type="number"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            className="mt-5"
          />
          <button
            onClick={() => submitCode()}
            className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded cursor-pointer mt-5"
          >
            Submit
          </button>
          {error && <p className="text-red-500 mt-5">{error}</p>}
        </>
      )}
    </div>
  );
}
