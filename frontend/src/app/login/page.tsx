import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  const error = typeof sp.error === "string" ? sp.error : undefined;

  return (
    <div className="flex min-h-[60vh] items-center justify-center">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="font-mono">
            agentguard<span className="text-muted-foreground">_console</span>
          </CardTitle>
          <CardDescription>Sign in to manage agent authorization.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {error && (
            <p role="alert" className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
              Sign-in failed. Check the console logs or try again.
            </p>
          )}
          <a
            href="/api/auth/login"
            className="inline-flex h-9 w-full items-center justify-center rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
          >
            Sign in with SSO
          </a>
          <p className="text-xs text-muted-foreground">
            Authentication uses OpenID Connect. Admin actions (delegation) require a
            configured admin claim.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
