import * as baseX from "base-x";

const base62 = baseX("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");

export function encode_binary(buffer: Buffer): string {
  return base62.encode(buffer);
}

export function decode_binary(string: string): Buffer {
  return base62.decode(string);
}