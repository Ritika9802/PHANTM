const DEFAULT_PROVIDER = "groq";

export function getLlmProvider() {
  return (process.env.LLM_PROVIDER || DEFAULT_PROVIDER).toLowerCase();
}

export function getGroqModel() {
  return process.env.GROQ_MODEL || "llama3-70b-8192";
}

export function getOllamaModel() {
  return process.env.OLLAMA_MODEL || "llama3.1:8b";
}

export function getLlmModelLabel() {
  const provider = getLlmProvider();
  if (provider === "ollama") return `Ollama · ${getOllamaModel()}`;
  return `Groq · ${getGroqModel()}`;
}