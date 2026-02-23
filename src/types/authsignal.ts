export interface AuthsignalTrackResult {
  state: string;
  url?: string;
  token?: string;
  id?: string;
}

export interface AuthsignalValidateResult {
  state?: string;
  isValid?: boolean;
  userId?: string;
  action?: string;
}
