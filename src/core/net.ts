/** Small IPv4 helpers. IPv6 is treated as "not parseable" and never matches a CIDR. */

export function ipv4ToInt(ip: string): number | null {
  const parts = ip.trim().split('.')
  if (parts.length !== 4) return null
  let n = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    const octet = Number(part)
    if (octet > 255) return null
    n = n * 256 + octet
  }
  return n
}

export function ipInCidr(ip: string, cidr: string): boolean {
  const [base, bitsText = '32'] = cidr.split('/')
  const ipN = ipv4ToInt(ip)
  const baseN = ipv4ToInt(base)
  const bits = Number(bitsText)
  if (ipN === null || baseN === null || !(bits >= 0 && bits <= 32)) return false
  if (bits === 0) return true
  const size = 2 ** (32 - bits)
  return Math.floor(ipN / size) === Math.floor(baseN / size)
}

const PRIVATE_RANGES = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16']

/** True for RFC 1918, loopback and link-local IPv4 addresses. */
export function isPrivateIp(ip: string): boolean {
  return PRIVATE_RANGES.some((range) => ipInCidr(ip, range))
}
