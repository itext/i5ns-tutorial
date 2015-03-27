using System;
using System.Collections.Generic;
using System.IO;
using com.itextpdf.text.pdf.security;
using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace signatures.chapter4 {
    public class C4_09_DeferredSigning {
        public const String CERT = "../../../../resources/bruno.crt";
        public const String KEYSTORE = "../../../../resources/pkcs12";
        public static char[] PASSWORD = "password".ToCharArray();

        public const String SRC = "../../../../resources/hello.pdf";
        public const String OUT_DIR = "../../../../results/chapter4";
        public const String TEMP = "../../../../results/chapter4/hello_empty_sig.pdf";
        public const String DEST = "../../../../results/chapter4/hello_sig_ok.pdf";

        private class MyExternalSignatureContainer : IExternalSignatureContainer {
            protected AsymmetricKeyEntry pk;
            protected ICollection<X509Certificate> chain;

            public MyExternalSignatureContainer(AsymmetricKeyEntry pk, ICollection<X509Certificate> chain) {
                this.pk = pk;
                this.chain = chain;
            }

            public byte[] Sign(Stream data) {
                PrivateKeySignature signature = new PrivateKeySignature(pk.Key, "SHA256");
                String hashAlgorithm = signature.GetHashAlgorithm();
                PdfPKCS7 sgn = new PdfPKCS7(null, chain, hashAlgorithm, false);
                byte[] hash = DigestAlgorithms.Digest(data, hashAlgorithm);
                DateTime signingTime = DateTime.Now;
                byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, signingTime, null, null, CryptoStandard.CMS);
                byte[] extSignature = signature.Sign(sh);
                sgn.SetExternalDigest(extSignature, null, signature.GetEncryptionAlgorithm());
                return sgn.GetEncodedPKCS7(hash, signingTime, null, null, null, CryptoStandard.CMS);
            }

            public void ModifySigningDictionary(PdfDictionary signDic) {
            }
        }

        public void EmptySignature(String src, String dest, String fieldname, IList<X509Certificate> chain) {
            PdfReader reader = new PdfReader(src);
            FileStream os = new FileStream(dest, FileMode.Create);
            PdfStamper stamper = PdfStamper.CreateSignature(reader, os, '\0');
            PdfSignatureAppearance appearance = stamper.SignatureAppearance;
            appearance.SetVisibleSignature(new Rectangle(36, 748, 144, 780), 1, fieldname);
            appearance.Certificate = chain[0];
            IExternalSignatureContainer external = new ExternalBlankSignatureContainer(PdfName.ADOBE_PPKLITE,
                PdfName.ADBE_PKCS7_DETACHED);
            MakeSignature.SignExternalContainer(appearance, external, 8192);
        }

        public void CreateSignature(String src, String dest, String fieldname, AsymmetricKeyEntry pk,
            IList<X509Certificate> chain) {
            PdfReader reader = new PdfReader(src);
            FileStream os = new FileStream(dest, FileMode.Create);
            IExternalSignatureContainer external = new MyExternalSignatureContainer(pk, chain);
            MakeSignature.SignDeferred(reader, fieldname, os, external);
        }


        public static void Main(String[] args) {
            Directory.CreateDirectory(OUT_DIR);

            // we load our private key from the key store
            Pkcs12Store store = new Pkcs12Store(new FileStream(KEYSTORE, FileMode.Open), PASSWORD);
            String alias = "";
            // searching for private key
            foreach (string al in store.Aliases)
                if (store.IsKeyEntry(al) && store.GetKey(al).Key.IsPrivate) {
                    alias = al;
                    break;
                }
            IList<X509Certificate> chain = new List<X509Certificate>();
            foreach (X509CertificateEntry c in store.GetCertificateChain(alias))
                chain.Add(c.Certificate);
            AsymmetricKeyEntry pk = store.GetKey(alias);


            C4_09_DeferredSigning app = new C4_09_DeferredSigning();
            app.EmptySignature(SRC, TEMP, "sig", chain);
            app.CreateSignature(TEMP, DEST, "sig", pk, chain);
        }
    }
}
