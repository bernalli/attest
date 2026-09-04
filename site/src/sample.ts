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
  // Parsed as a decimal integer and compared as one, never through `Number`.
  // A header of four hundred digits is a syntactically valid claim, and
  // `Number` turns it into `Infinity` — which is not finite, so a guard written
  // around `Number.isFinite` skips the refusal and fetches the body. The larger
  // the lie, the more certainly it got through. `BigInt` has no such ceiling,
  // and a header that is not a run of digits is not a claim this reads: it is a
  // response that is not the one asked for.
  const declaredText = bundleRes.headers.get('content-length')
  if (declaredText !== null) {
    if (!/^[0-9]+$/.test(declaredText))
      throw new Error('sample bundle returned an invalid Content-Length')
    const declared = BigInt(declaredText)
    if (declared > BigInt(maxStoredBytes))
      throw new BundleTooLargeError(storedLimitMessage(declared, maxStoredBytes))
  }
  const bytes = new Uint8Array(await bundleRes.arrayBuffer())
  if (bytes.byteLength > maxStoredBytes)
    throw new BundleTooLargeError(storedLimitMessage(bytes.byteLength, maxStoredBytes))
  return {
    bytes,
    binding: (await bindingRes.json()) as SampleBinding,
  }
}
