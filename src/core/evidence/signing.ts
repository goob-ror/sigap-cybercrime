import { sha256Hex } from '@/core/evidence/hash'

/**
 * Signature on an evidence package. A manifest and a hash chain show that nothing changed by accident,
 * but anyone can recompute them after editing the contents. A signature ties the package to whoever
 * holds a private key, which a forger does not, so an edited package can only be re-signed with a
 * different key. That difference shows only if the recipient compares the fingerprint with the one the
 * sender registered beforehand through another channel, such as a berita acara. Nothing here proves who
 * a person is: there is no certificate authority behind the key, and no trusted clock behind the time.
 */

export const SIGNATURE_FILE = 'TANDA-TANGAN.json'
const ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256' } as const
const SIGN = { name: 'ECDSA', hash: 'SHA-256' } as const

export type PackageSignature = {
  algoritma: 'ECDSA-P256-SHA256'
  kunciPublik: JsonWebKey
  sidikJari: string
  ditandatangani: string
  /** Base64. */
  tandaTangan: string
}

export type SignatureCheck =
  | { status: 'tidak-ada' }
  | { status: 'tidak-sah'; reason: string; fingerprint?: string }
  | { status: 'sah'; fingerprint: string; signedAt: string }

/** The private half cannot be exported, so copying this browser's data does not copy the ability to sign with it. */
export function createSigningKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ALGORITHM, false, ['sign', 'verify'])
}

/** `AB12:CD34:…`: short enough to read out or write on a berita acara. */
export async function fingerprintOf(publicKey: JsonWebKey): Promise<string> {
  const hash = await sha256Hex(`${publicKey.crv}|${publicKey.x}|${publicKey.y}`)
  return hash.slice(0, 32).toUpperCase().match(/.{4}/g)!.join(':')
}

export async function keyFingerprint(keys: CryptoKeyPair): Promise<string> {
  return fingerprintOf(await crypto.subtle.exportKey('jwk', keys.publicKey))
}

const toSign = (manifestHash: string, chainHash: string, signedAt: string) => new TextEncoder().encode(`SIGAP-PAKET-1\n${manifestHash}\n${chainHash}\n${signedAt}`)

const toBase64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes))
const fromBase64 = (text: string) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0))

/** Signs the manifest and the custody chain, which between them commit to every file in the package. */
export async function signPackage(keys: CryptoKeyPair, manifestText: string, chainText: string, signedAt: string): Promise<PackageSignature> {
  const kunciPublik = await crypto.subtle.exportKey('jwk', keys.publicKey)
  const signature = await crypto.subtle.sign(SIGN, keys.privateKey, toSign(await sha256Hex(manifestText), await sha256Hex(chainText), signedAt))
  return { algoritma: 'ECDSA-P256-SHA256', kunciPublik, sidikJari: await fingerprintOf(kunciPublik), ditandatangani: signedAt, tandaTangan: toBase64(new Uint8Array(signature)) }
}

export async function checkSignature(file: Uint8Array | undefined, manifestText: string, chainText: string): Promise<SignatureCheck> {
  if (!file) return { status: 'tidak-ada' }
  try {
    const sig = JSON.parse(new TextDecoder().decode(file)) as PackageSignature
    // Computed from the key, never read from the file: a forger can write any fingerprint they like there.
    const fingerprint = await fingerprintOf(sig.kunciPublik)
    const key = await crypto.subtle.importKey('jwk', sig.kunciPublik, ALGORITHM, false, ['verify'])
    const valid = await crypto.subtle.verify(SIGN, key, fromBase64(sig.tandaTangan), toSign(await sha256Hex(manifestText), await sha256Hex(chainText), sig.ditandatangani))
    return valid ? { status: 'sah', fingerprint, signedAt: sig.ditandatangani } : { status: 'tidak-sah', reason: 'Tanda tangan tidak cocok dengan isi paket', fingerprint }
  } catch {
    return { status: 'tidak-sah', reason: `${SIGNATURE_FILE} tidak dapat dibaca` }
  }
}
