// frontend/src/pages/Reports.jsx
import React from "react";
import { FileText, Printer } from "lucide-react";

export default function Reports() {
  return (
    <div className="p-6 space-y-4">
      <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-6 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <FileText className="w-5 h-5 text-cyan-400" />
          <div>
            <h3 className="text-sm font-semibold text-white">Executive Security Assessment Report</h3>
            <p className="text-xs text-zinc-400 mt-0.5">
              Export current assessment findings as a formatted PDF deliverable.
            </p>
          </div>
        </div>
        <button
          onClick={() => window.print()}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-cyan-500 hover:bg-cyan-400 text-black text-xs font-medium cursor-pointer"
        >
          <Printer className="w-4 h-4" />
          <span>Print / Save PDF</span>
        </button>
      </div>
    </div>
  );
}