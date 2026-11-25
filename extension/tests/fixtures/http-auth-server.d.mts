export interface HttpAuthServerOptions {
  host?: string;
  port?: number;
  mode?: "basic" | "digest";
  realm?: string;
  users?: Record<string, string>;
  name?: string;
}

export interface HttpAuthPathStats {
  requests: number;
  challenges: number;
  attempts: number;
  successes: number;
  failures: number;
}

export interface HttpAuthStats extends HttpAuthPathStats {
  name: string;
  host: string;
  port: number;
  mode: "basic" | "digest";
  realm: string;
  byPath: Record<string, HttpAuthPathStats>;
}

export declare class HttpAuthServer {
  constructor(options?: HttpAuthServerOptions);
  readonly host: string;
  readonly mode: "basic" | "digest";
  readonly realm: string;
  readonly name: string;
  readonly port: number;
  readonly origin: string;
  start(): Promise<HttpAuthServer>;
  stop(): Promise<void>;
  url(path?: string): string;
  stats(): HttpAuthStats;
  resetStats(): void;
  pathStats(path: string): HttpAuthPathStats;
}

export declare function startHttpAuthServers(): Promise<{
  single: HttpAuthServer;
  digest: HttpAuthServer;
  wrong: HttpAuthServer;
  parallel: HttpAuthServer;
  noMatch: HttpAuthServer;
}>;

export declare function fetchStats(server: HttpAuthServer): Promise<HttpAuthStats>;
