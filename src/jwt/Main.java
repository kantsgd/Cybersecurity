package jwt;

import io.jsonwebtoken.*;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;

import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;

public class Main {
    private static final String MESSAGE = "HELLO WORLD";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, IOException, InvalidKeyException, SignatureException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "SunEC");
        ECGenParameterSpec ecsp = new ECGenParameterSpec("secp384r1");
        generator.initialize(ecsp);

        KeyPair kp = generator.generateKeyPair();
        PrivateKey privKey = kp.getPrivate();
        PublicKey pubKey = kp.getPublic();

        byte[] sign = createSignature(privKey);
        boolean isSignatureVerified = verifySignature(pubKey, sign);

        String jwt = createJwt(privKey);
        boolean isJwtVerified = verifyJwt(jwt, pubKey);

        StringWriter strWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(strWriter)) {
            pemWriter.writeObject(new JcaPKCS8Generator(privKey, null));
        }

        StringWriter strWriter2 = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(strWriter2)) {
            pemWriter.writeObject(pubKey);
        }

        System.out.println(strWriter);
        System.out.println(strWriter2);
    }

    private static byte[] createSignature(PrivateKey privateKey)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature signGenerator = Signature.getInstance("SHA256withECDSA", "SunEC");
        signGenerator.initSign(privateKey);
        signGenerator.update(MESSAGE.getBytes());
        return signGenerator.sign();
    }

    private static boolean verifySignature(PublicKey publicKey, byte[] signature)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature signGenerator = Signature.getInstance("SHA256withECDSA", "SunEC");
        signGenerator.initVerify(publicKey);
        signGenerator.update(MESSAGE.getBytes());
        return signGenerator.verify(signature);
    }

    private static String createJwt(PrivateKey privateKey) {
        String jwt = Jwts.builder().setSubject("sait")
                .setIssuer("localhost")
                .signWith(privateKey, SignatureAlgorithm.ES384)
                .compact();
        return jwt;
    }

    private static boolean verifyJwt(String jwt, PublicKey publicKey) {
        try {
            Jws<Claims> token = Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(jwt);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}