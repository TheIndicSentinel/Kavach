import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";
import { Button } from "./ui/Button";
import { Card, CardDescription, CardHeader, CardTitle } from "./ui/Card";

type ErrorBoundaryProps = {
  children: ReactNode;
};

type ErrorBoundaryState = {
  error: Error | null;
};

export class ErrorBoundary extends Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("Console error:", error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex min-h-screen items-center justify-center bg-surface p-6">
          <Card className="max-w-lg">
            <CardHeader>
              <div className="mb-2 flex h-10 w-10 items-center justify-center rounded-lg bg-decision-block-bg text-decision-block">
                <AlertTriangle className="h-5 w-5" aria-hidden />
              </div>
              <CardTitle>Something went wrong</CardTitle>
              <CardDescription>
                The console encountered an unexpected error. Reload to try again.
              </CardDescription>
            </CardHeader>
            <pre className="mb-4 overflow-auto rounded-lg bg-stone-100 p-3 text-xs text-stone-700">
              {this.state.error.message}
            </pre>
            <Button onClick={() => window.location.reload()}>Reload console</Button>
          </Card>
        </div>
      );
    }

    return this.props.children;
  }
}
