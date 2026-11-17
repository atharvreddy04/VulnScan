import React from "react";
import { Activity, Shield } from "lucide-react";

export default function Navbar({ apiOnline, activeTitle }) {
  return (
    <header className="h-16 bg-zinc-950/90 border-b border-zinc-900 px-6 flex items-center justify-between sticky top-0 z-10 backdrop-blur">
      <div className="flex items-center gap-2.5">
        <Shield className="w-4 h-4 text-cyan-400" />
        <h2 className="text-sm font-semibold text-white tracking-tight">
          {activeTitle}
        </h2>
      </div>

      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 text-xs px-3 py-1.5 rounded-md bg-black border border-zinc-800">
          <span
            className={`w-2 h-2 rounded-full ${
              apiOnline === true
                ? "bg-emerald-400"
                : apiOnline === false
                ? "bg-red-500"
                : "bg-zinc-500 animate-pulse"
            }`}
          />
          <Activity className="w-3.5 h-3.5 text-zinc-400" />
          <span className="text-zinc-300">
            {apiOnline === true
              ? "FastAPI Engine: Connected"
              : apiOnline === false
              ? "FastAPI Engine: Offline"
              : "Checking API..."}
          </span>
        </div>
      </div>
    </header>
  );
}