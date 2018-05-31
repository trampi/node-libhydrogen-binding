import {Buffer} from "safe-buffer";

export function init(): number;
export function random_u32(): number;
export function random_uniform(upperBound: number): number;
export function secretbox_keygen(): Buffer;
export function secretbox_encrypt(msg: string, key: Buffer, msgId: number, context: string): Buffer;
export function secretbox_decrypt(ciphertext: Buffer, key: Buffer, msgId: number, context: string): string;
export function secretbox_probe_create(ciphertext: Buffer, context: string, key: Buffer): Buffer;
export function secretbox_probe_verify(probe: Buffer, ciphertext: Buffer, context: string, key: Buffer);

export const secretbox_keybytes_size: number;
export const secretbox_contextbytes_size: number;
export const secretbox_headerbytes_size: number;
export const secretbox_probebytes_size: number;
