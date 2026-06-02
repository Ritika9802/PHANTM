import { useEffect, useRef, useState } from "react";

export function useScanWS(scanId) {
  const [logs, setLogs] = useState([]);
  const [stages, setStages] = useState({});
  const [findings, setFindings] = useState([]);
  const [complete, setComplete] = useState(null);
  const wsRef = useRef(null);

  useEffect(() => {
    if (!scanId) return;
    setLogs([]); setStages({}); setFindings([]); setComplete(null);

    const ws = new WebSocket(`ws://localhost:3001?scanId=${scanId}`);
    wsRef.current = ws;

    ws.onmessage = (e) => {
      try {
        const { event, data, ts } = JSON.parse(e.data);
        if (event === "log") {
          setLogs(l => [...l, { ...data, ts: new Date(ts).toLocaleTimeString() }]);
        } else if (event === "stage") {
          setStages(s => ({ ...s, [data.stage]: data.status }));
        } else if (event === "finding") {
          setFindings(f => [...f, data]);
        } else if (event === "complete") {
          setComplete(data);
        }
      } catch {}
    };

    ws.onerror = () => {};
    ws.onclose = () => {};

    return () => ws.close();
  }, [scanId]);

  return { logs, stages, findings, complete };
}
