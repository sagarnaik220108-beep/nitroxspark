import type { Metadata } from "next";
import { CommandCenter } from "@/components/sentinel/CommandCenter";

export const metadata: Metadata = {
  title: "Command Center — Sentinel AI",
  description:
    "Interactive AI Security Command Center for static vulnerability scanning, one-click deterministic remediation, attack simulation, and multi-format security reports.",
};

export default function DashboardPage() {
  return <CommandCenter />;
}
