/**
 * Gate Auth v1 tokens, with no dependencies beyond the JDK.
 *
 * <ul>
 *   <li>Apps verify tokens with {@link io.github.technic47.gateauth.core.TokenVerifier} and the gate's public keys
 *       ({@link io.github.technic47.gateauth.core.GateKeySet}).</li>
 *   <li>The gate signs them with {@link io.github.technic47.gateauth.core.TokenSigner} and its
 *       {@link io.github.technic47.gateauth.core.GateSigningKey}.</li>
 *   <li>{@link io.github.technic47.gateauth.core.KeyTool} generates a key pair.</li>
 * </ul>
 *
 * <p>Tokens are JWS compact serialization signed with Ed25519 ({@code alg=EdDSA}). The format is defined by the
 * Gate Auth v1 specification, {@code docs/gate-auth-spec-v1.md} in the project repository.
 */
package io.github.technic47.gateauth.core;
