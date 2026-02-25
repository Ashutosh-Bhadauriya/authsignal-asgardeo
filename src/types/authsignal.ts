export interface AuthsignalTrackResult {
  state: string;
  idempotencyKey?: string;
  url?: string;
  token?: string;
}

export interface AuthsignalGetActionResult {
  state: string;
}
