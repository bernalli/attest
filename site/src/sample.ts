import { BundleTooLargeError, storedLimitMessage } from './bundle.js'
import { MAX_STORED_BYTES } from './container.js'

export interface SampleBinding {
  identifier: string
  identifier_type: string
  salt_b64u: string
}

/**
 * The bundle this deployment ships as its own sample, and the binding that
 * opens it.
 *
 * A fetch is an intake like any other, so v0.1 §14.4's floor applies here too
 * and in the same order: what the response DECLARES is checked before the body
 * is asked for, and what it actually delivered is checked once it has arrived.
 * Both halves are needed and neither replaces the other — `Content-Length` is
 * a claim by whoever answered, so believing it alone would let a lying header
 * hand this tab a gigabyte, and checking only the delivered bytes would spend
 * the gigabyte first, which is exactly what the floor exists to prevent. A
 * response that declares nothing is not refused for that: it is read under the
 * second check, which is a measurement rather than a claim.
 *
 * `maxStoredBytes` is an argument for the same reason `parseBundle`'s is: a
 * bound nobody can move is a bound nobody can test at its edge.
 */
export async function loadSample(
  baseUrl = 'sample/',
  maxStoredBytes: number = MAX_STORED_BYTES,
): Promise<{ bytes: Uint8Array; binding: SampleBinding }> {
  const [bundleRes, bindingRes] = await Promise.all([
    fetch(`${baseUrl}demo.attest`),
    fetch(`${baseUrl}demo-binding.json`),
  ])
  if (!bundleRes.ok || !bindingRes.ok) throw new Error('sample assets are missing from this deployment')
  const declared = Number(bundleRes.headers.get('content-length'))
  if (Number.isFinite(declared) && declared > maxStoredBytes)
    throw new BundleTooLargeError(storedLimitMessage(declared, maxStoredBytes))
  const bytes = new Uint8Array(await bundleRes.arrayBuffer())
  if (bytes.byteLength > maxStoredBytes)
    throw new BundleTooLargeError(storedLimitMessage(bytes.byteLength, maxStoredBytes))
  return {
    bytes,
    binding: (await bindingRes.json()) as SampleBinding,
  }
}
