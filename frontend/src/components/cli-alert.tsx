"use client";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

export function CliAlert({ message }: { message: string }) {
  return (
    <Alert variant="destructive" className="mb-6">
      <AlertTitle>agentguard CLI not available</AlertTitle>
      <AlertDescription className="whitespace-pre-wrap font-mono text-xs">
        {message}
        {"\n"}
        Install it from the repo root:{" "}
        <code>cargo install --path crates/agentguard-cli</code>, then make sure
        an initialized store exists (<code>agentguard init --name acme</code>)
        and restart the dev server from the repository root so the{" "}
        <code>.agentguard</code> directory resolves.
      </AlertDescription>
    </Alert>
  );
}
