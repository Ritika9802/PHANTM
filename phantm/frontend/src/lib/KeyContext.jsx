import { createContext, useContext, useState } from "react";

const Ctx = createContext(null);

export function KeyProvider({ children }) {
  const [apiKey, setApiKey] = useState(() => localStorage.getItem("phantm_groq_key") || "");
  const saveKey = (k) => { setApiKey(k); localStorage.setItem("phantm_groq_key", k); };
  return <Ctx.Provider value={{ apiKey, saveKey }}>{children}</Ctx.Provider>;
}

export const useKey = () => useContext(Ctx);
