import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Encoder;

import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class Test {

    public static void main(String[] args) throws Exception {


        // Create instance of SunPKCS11 provider
        String pkcs11Config = "name=harshraj\nlibrary=c:\\WINDOWS\\system32\\eTPKCS11.dll\nslot=2";
        java.io.ByteArrayInputStream pkcs11ConfigStream = new java.io.ByteArrayInputStream(pkcs11Config.getBytes());
        sun.security.pkcs11.SunPKCS11 providerPKCS11 = new sun.security.pkcs11.SunPKCS11(pkcs11ConfigStream);
        java.security.Security.addProvider(providerPKCS11);

// Get provider KeyStore and login with PIN
        String pin = "Etoken@123";
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance("PKCS11", providerPKCS11);

        KeyStore keyStore1=keyStore.getInstance("PKCS11",providerPKCS11);
        keyStore1.load(null, pin.toCharArray());

// Enumerate items (certificates and private keys) in the KeyStore
        java.util.Enumeration<String> aliases = keyStore1.aliases();


        while(aliases.hasMoreElements()) {
            String alias = (String)aliases.nextElement();
            System.out.println("alias name: " + alias);
            Certificate certificate = keyStore1.getCertificate(alias);
            System.out.println(certificate.toString());
            X509Certificate certificate1 = (X509Certificate) certificate;
            System.out.println(certificate1.getNotBefore());
            System.out.println(certificate1.getNotAfter());
            System.out.println(certificate1.getSerialNumber());
            System.out.println("----------------");
            Key key = keyStore1.getKey(alias, "password".toCharArray());
            PrivateKey privKey = (PrivateKey) key;
            System.out.println(privKey.toString());
            Provider provider = keyStore1.getProvider();
            System.out.println(provider.toString());
            new Test().sign(privKey,"this data will be signed!!!");
        }




    }

    public void sign(PrivateKey pk,String data) throws Exception{
        Signature sig = Signature.getInstance("SHA1WithRSA");
        sig.initSign(pk);
        sig.update(data.getBytes("UTF8"));
        byte[] signatureBytes = sig.sign();
        System.out.println("Signature:" + new BASE64Encoder().encode(signatureBytes));
    }
}
