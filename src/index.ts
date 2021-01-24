/////////////////////////////////////////////////////////
//                                                     //
//   asymmetric token-based one-time authentication    //
//                                                     //
/////////////////////////////////////////////////////////

import Advanceable from "advanceable";
import crypto, { KeyObject } from "@justablob/commoncrypto";

const magic_byte = 0x9c;
const randomness_size = 16;

export function get_period (interval: number, time?: number): number {
  let cur_time = (time ?? Date.now()) / 1000;
  let prd_time = Math.trunc(cur_time / interval);

  return prd_time;
}

function _decode_period (period: Buffer): number {
  return period.readUIntBE(0, 6);
}

function _encode_period (period: number): Buffer {
  let buf = Buffer.allocUnsafe(6);
  buf.writeUIntBE(period, 0, 6);
  return buf;
}

export function generate_keypair () {
  return crypto.signature_generate_keypair();
}

export function encode_keypair (publicKey?: KeyObject, privateKey?: KeyObject): [Buffer, Buffer] {
  let publicKeyEncoded;
  let privateKeyEncoded;

  if (publicKey) {
    publicKeyEncoded = crypto.signature_export_key(publicKey);
  }
  if (privateKey) {
    privateKeyEncoded = crypto.signature_export_key(privateKey);
  }

  return [publicKeyEncoded, privateKeyEncoded];
}

export function decode_keypair (publicKey?: Buffer, privateKey?: Buffer): [KeyObject, KeyObject] {
  let publicKeyDecoded;
  let privateKeyDecoded;

  if (publicKey) {
    publicKeyDecoded = crypto.signature_import_key("public", publicKey);
  }
  if (privateKey) {
    privateKeyDecoded = crypto.signature_import_key("private", privateKey);
  }

  return [publicKeyDecoded, privateKeyDecoded];
}

function _join_inner_data (
  interval: number,
  additional_data: Buffer,
  randomness: Buffer,
  period: number,
) {
  let writer = new Advanceable(10 + randomness_size + crypto._param.HASH_ALGORITHM_OUTPUT_LENGTH, true);

  let ad_hash = crypto.hash(additional_data);

  writer.writeUInt16BE(interval);
  writer.writeUInt16BE(additional_data.length);
  writer.write(ad_hash);
  writer.write(randomness);
  writer.write(_encode_period(period));

  return writer.buffer;
}

function _join_outer_data (
  interval: number,
  randomness: Buffer,
  period: number,
  signature: Buffer,
) {
  let writer = new Advanceable(9 + randomness_size + crypto._param.SIGNATURE_ALGORITHM_SIGNATURE_LENGTH, true);

  writer.writeByte(magic_byte);
  writer.writeUInt16BE(interval);
  writer.write(randomness);
  writer.write(_encode_period(period));
  writer.write(signature);

  return writer.buffer;
}

function _read_outer_data (data: Buffer): [
  number,
  Buffer,
  number,
  Buffer
] {
  let reader = new Advanceable(data);

  if (reader.readByte() !== magic_byte) return null;

  let interval = reader.readUInt16BE();
  let randomness = reader.read(randomness_size);
  let period = _decode_period(reader.read(6));
  let signature = reader.read(crypto._param.SIGNATURE_ALGORITHM_SIGNATURE_LENGTH);

  return [
    interval,
    randomness,
    period,
    signature
  ];
}

export function authenticate (
  private_key: KeyObject,
  interval: number = 10,
  additional_data: Buffer = Buffer.alloc(0),
): Buffer {
  let randomness = crypto.random(randomness_size);
  let period = get_period(interval);

  let inner_data = _join_inner_data(
    interval,
    additional_data,
    randomness,
    period,
  );

  let signature = crypto.signature_sign(private_key, inner_data);

  let output_data = _join_outer_data(
    interval,
    randomness,
    period,
    signature,
  );

  return output_data;
}

export function verify (
  token: Buffer,
  public_key: KeyObject,
  interval_max: number = 10,
  additional_data: Buffer = Buffer.alloc(0),
  _desync_lower: number = 1,
  _desync_upper: number = 1,
): boolean {
  let desync_lower = Math.abs(_desync_lower);
  let desync_upper = Math.abs(_desync_upper || _desync_lower);

  let [
    interval,
    randomness,
    period,
    signature,
  ] = _read_outer_data(token);

  if (randomness.length !== randomness_size) return false;

  if (interval > interval_max) return false;

  let cur_period = get_period(interval);
  if (cur_period - period > desync_upper) return false;
  if (period - cur_period > desync_lower) return false;

  let inner_data = _join_inner_data(
    interval,
    additional_data,
    randomness,
    period,
  );

  return crypto.signature_verify(public_key, inner_data, signature);
}