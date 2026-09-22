import Image from "next/image";
import Link from "next/link";

export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <Link href="/" className="brand-mark shrink-0" aria-label="AgentGuard home">
      <Image
        src="/agentguard-mark.svg"
        alt=""
        width={32}
        height={32}
        priority
        className="brand-icon"
      />
      {!compact && <span className="hidden sm:inline">AgentGuard</span>}
    </Link>
  );
}
