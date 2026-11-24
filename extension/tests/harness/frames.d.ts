export declare const MAX_FRAME_BYTES: number;

export declare const HOST_ERROR: {
  readonly FRAME_TOO_LARGE: "1001";
  readonly MALFORMED_FRAME: "1002";
  readonly UNKNOWN_HOST_ACTION: "1003";
  readonly HOST_INTERNAL_ERROR: "1004";
  readonly APP_UNAVAILABLE: "1005";
  readonly ENCRYPTION_REQUIRED: "1006";
};

export interface FrameError {
  type: "error";
  errorCode: string;
  error: string;
}

export interface DecodedFrame {
  type: "frame";
  value: Record<string, unknown>;
}

export type Decoded = DecodedFrame | FrameError;

export declare function encodeFrame(value: unknown): Buffer;
export declare function encodePayload(payload: Buffer | Uint8Array): Buffer;
export declare function incrementNonce(nonceB64: string): string;
export declare function sleep(ms: number): Promise<void>;

export declare class FrameDecoder {
  buffer: Buffer;
  maxBytes: number;
  skipRemaining: number;
  constructor(options?: { maxBytes?: number });
  push(chunk: Buffer | Uint8Array): Decoded[];
}
