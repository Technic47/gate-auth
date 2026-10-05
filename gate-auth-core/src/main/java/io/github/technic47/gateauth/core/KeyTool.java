package io.github.technic47.gateauth.core;

/**
 * Command-line generator for the gate's signing key.
 *
 * <pre>
 * java -cp gate-auth-core.jar io.github.technic47.gateauth.core.KeyTool
 * </pre>
 * Prints the private JWK (secret, goes to GateService only) and the public key as PEM and JWKS (goes to apps).
 */
public final class KeyTool {

    private KeyTool() {
    }

    /**
     * Generates a key and prints it to standard output.
     *
     * @param args ignored
     */
    public static void main(String[] args) {
        GateSigningKey key = GateSigningKey.generate();
        System.out.println("# kid: " + key.kid());
        System.out.println();
        System.out.println("# PRIVATE JWK - SECRET. Only for GateService (GATE_SIGNING_KEY). Never commit.");
        System.out.println(key.toPrivateJwk());
        System.out.println();
        System.out.println("# PUBLIC KEY (PEM) - for apps (gate.auth.public-keys)");
        System.out.print(Ed25519Keys.toPem(key.publicKey()));
        System.out.println();
        System.out.println("# PUBLIC JWKS - same key as JSON");
        System.out.println(GateKeySet.of(key.publicKey()).toJwks());
    }
}
