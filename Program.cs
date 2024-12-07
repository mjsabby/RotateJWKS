namespace RotateJWKS
{
    using System;
    using System.Globalization;
    using System.IO;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;

    internal static class Program
    {
        public static void Main(string[] args)
        {
            const string usage = "Usage: RotateJWKS subjectName expiryInSeconds /encryptedDisk/keysFolderPath /toServePublicly/jwks.json RSAorEC";

            if (args.Length != 5)
            {
                Environment.FailFast(usage);
                return;
            }

            var subjectName = args[0];
            var expiryInSeconds = int.Parse(args[1], CultureInfo.InvariantCulture);
            var privateKeysPath = args[2];
            var publicJwksPath = args[3];
            var keyType = args[4];

            if (!string.Equals(keyType, "RSA", StringComparison.OrdinalIgnoreCase) && !string.Equals(keyType, "EC", StringComparison.OrdinalIgnoreCase))
            {
                Environment.FailFast(usage);
                return;
            }

            bool isRSA = string.Equals(keyType, "RSA", StringComparison.OrdinalIgnoreCase);

            var currentlyPassivePFXPath = Path.Combine(privateKeysPath, "currentlyPassive.pfx"); // used at the end of this program
            var currentlyActivePFXPath = Path.Combine(privateKeysPath, "currentlyActive.pfx");

            DateTime notBefore = DateTime.UtcNow;
            DateTime notAfter = notBefore.AddSeconds(expiryInSeconds);

            // first run
            if (!File.Exists(currentlyActivePFXPath))
            {
                File.WriteAllBytes(currentlyActivePFXPath, isRSA ? GenerateRSA(subjectName, notBefore, notAfter) : GenerateEC(subjectName, notBefore, notAfter));
            }

            var currentlyActivePFX = File.ReadAllBytes(currentlyActivePFXPath);
            using var currentlyActivePublicKey = new X509Certificate2(currentlyActivePFX);

            string currentlyActiveJwk;
            byte[] newPFX;
            string newJwk;

            if (isRSA)
            {
                currentlyActiveJwk = RSAToJWK(currentlyActivePFX);
                newPFX = GenerateRSA(subjectName, notBefore, notAfter);
                newJwk = RSAToJWK(newPFX);
            }
            else
            {
                currentlyActiveJwk = ECToJWK(currentlyActivePFX);
                newPFX = GenerateEC(subjectName, notBefore, notAfter);
                newJwk = ECToJWK(newPFX);
            }

            var outputJwks = $"{{\n  \"keys\": [\n{newJwk},\n{currentlyActiveJwk}\n  ]\n}}"; // new key first, then the currently active key that is becoming passive

            // order doesn't matter, because this is to be done in a staging area
            File.WriteAllBytes(currentlyPassivePFXPath, currentlyActivePFX);
            File.WriteAllBytes(currentlyActivePFXPath, newPFX);
            File.WriteAllText(publicJwksPath, outputJwks);
        }

        private static string RSAToJWK(byte[] pfx)
        {
            using X509Certificate2 certificate = new(pfx);

            (string x5t, string x5c) = GenerateX5TAndC(certificate);

            RSA rsa = certificate.GetRSAPublicKey()!;
            var rsaParameters = rsa.ExportParameters(false);

            string n = Base64UrlEncode(rsaParameters.Modulus!);
            string e = Base64UrlEncode(rsaParameters.Exponent!);
            string k = Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes($$"""{"e":"{{e}}","kty":"RSA","n":"{{n}}"}""")));

            return $"    {{\n      \"alg\":\"RS256\",\n      \"use\":\"sig\",\n      \"kty\":\"RSA\",\n      \"kid\":\"{k}\",\n      \"e\":\"{e}\",\n      \"n\":\"{n}\",\n      \"x5t\":\"{x5t}\",\n      \"x5c\":[\"{x5c}\"]\n    }}";
        }

        private static string ECToJWK(byte[] pfx)
        {
            using X509Certificate2 certificate = new(pfx);

            (string x5t, string x5c) = GenerateX5TAndC(certificate);

            ECDsa ecdsa = certificate.GetECDsaPublicKey()!;
            var ecdsaParameters = ecdsa.ExportParameters(false);

            string x = Base64UrlEncode(ecdsaParameters.Q.X!);
            string y = Base64UrlEncode(ecdsaParameters.Q.Y!);
            string k = Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes($$"""{"crv":"P-256","kty":"EC","x":"{{x}}","y":"{{y}}"}""")));

            return $"    {{\n      \"alg\":\"ES256\",\n      \"use\":\"sig\",\n      \"kty\":\"EC\",\n      \"kid\":\"{k}\",\n      \"crv\":\"P-256\",\n      \"x\":\"{x}\",\n      \"y\":\"{y}\"\n      \"x5t\":\"{x5t}\",\n      \"x5c\":[\"{x5c}\"]\n    }}";
        }

        private static byte[] GenerateRSA(string subjectName, DateTime notBefore, DateTime notAfter)
        {
            using RSA rsa = RSA.Create(2048);
            CertificateRequest request = new(new X500DistinguishedName(subjectName), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            X509Certificate2 certificate = request.CreateSelfSigned(notBefore, notAfter);
            return certificate.Export(X509ContentType.Pfx);
        }

        private static byte[] GenerateEC(string subjectName, DateTime notBefore, DateTime notAfter)
        {
            using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            CertificateRequest request = new(new X500DistinguishedName(subjectName), ecdsa, HashAlgorithmName.SHA256);
            X509Certificate2 certificate = request.CreateSelfSigned(notBefore, notAfter);
            return certificate.Export(X509ContentType.Pfx);
        }

        private static (string, string) GenerateX5TAndC(X509Certificate2 certificate)
        {
            byte[] derEncodedCert = certificate.GetRawCertData();
            byte[] sha1Thumbprint = SHA1.HashData(derEncodedCert);
            string base64EncodedCert = Convert.ToBase64String(derEncodedCert);
            return (Base64UrlEncode(sha1Thumbprint), base64EncodedCert);
        }

        private static string Base64UrlEncode(ReadOnlySpan<byte> input) => Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}