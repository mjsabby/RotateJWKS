namespace RotateJWKS
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;

    internal static class Program
    {
        public static void Main(string[] args)
        {
            const string usage = "Usage: RotateJWKS /encryptedDisk/keysFolderPath /toServePublicly/jwks.json RSAorEC";

            if (args.Length != 3)
            {
                Environment.FailFast(usage);
                return;
            }

            var privateKeysPath = args[0];
            var publicJwksPath = args[1];
            var keyType = args[2];

            if (!string.Equals(keyType, "RSA", StringComparison.OrdinalIgnoreCase) && !string.Equals(keyType, "EC", StringComparison.OrdinalIgnoreCase))
            {
                Environment.FailFast(usage);
                return;
            }

            bool isRSA = string.Equals(keyType, "RSA", StringComparison.OrdinalIgnoreCase);

            var currentlyPassivePemPath = Path.Combine(privateKeysPath, "currentlyPassive.pem"); // used at the end of this program
            var currentlyActivePemPath = Path.Combine(privateKeysPath, "currentlyActive.pem");

            // first run
            if (!File.Exists(currentlyActivePemPath))
            {
                File.WriteAllText(currentlyActivePemPath, isRSA ? GenerateRSAPEM() : GenerateECPEM());
            }

            var currentlyActivePem = File.ReadAllText(currentlyActivePemPath);

            string currentlyActiveJwk;
            string newPem;
            string newJwk;

            if (isRSA)
            {
                currentlyActiveJwk = RSAPEMToJWK(currentlyActivePem);
                newPem = GenerateRSAPEM();
                newJwk = RSAPEMToJWK(newPem);
            }
            else
            {
                currentlyActiveJwk = ECPEMToJWK(currentlyActivePem);
                newPem = GenerateECPEM();
                newJwk = ECPEMToJWK(newPem);
            }

            var outputJwks = $"{{\n  \"keys\": [\n{newJwk},\n{currentlyActiveJwk}\n  ]\n}}"; // new key first, then the currently active key that is becoming passive

            // order doesn't matter, because this is to be done in a staging area
            File.WriteAllText(currentlyPassivePemPath, currentlyActivePem);
            File.WriteAllText(currentlyActivePemPath, newPem);
            File.WriteAllText(publicJwksPath, outputJwks);
        }

        private static string GenerateRSAPEM()
        {
            using var rsa = RSA.Create(2048);
            return $"-----BEGIN PRIVATE KEY-----\n{Convert.ToBase64String(rsa.ExportPkcs8PrivateKey())}\n-----END PRIVATE KEY-----";
        }

        private static string GenerateECPEM()
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return $"-----BEGIN PRIVATE KEY-----\n{Convert.ToBase64String(ecdsa.ExportPkcs8PrivateKey())}\n-----END PRIVATE KEY-----";
        }

        private static string RSAPEMToJWK(string pem)
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            var rsaParameters = rsa.ExportParameters(false);

            string n = Base64UrlEncode(rsaParameters.Modulus!);
            string e = Base64UrlEncode(rsaParameters.Exponent!);
            string k = Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes($$"""{"e":"{{e}}","kty":"RSA","n":"{{n}}"}""")));

            return $"    {{\n      \"alg\":\"RS256\",\n      \"use\":\"sig\",\n      \"kty\":\"RSA\",\n      \"kid\":\"{k}\",\n      \"e\":\"{e}\",\n      \"n\":\"{n}\"\n    }}";
        }

        private static string ECPEMToJWK(string pem)
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            ecdsa.ImportFromPem(pem);
            var ecdsaParameters = ecdsa.ExportParameters(false);

            string x = Base64UrlEncode(ecdsaParameters.Q.X!);
            string y = Base64UrlEncode(ecdsaParameters.Q.Y!);
            string k = Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes($$"""{"crv":"P-256","kty":"EC","x":"{{x}}","y":"{{y}}"}""")));

            return $"    {{\n      \"alg\":\"ES256\",\n      \"use\":\"sig\",\n      \"kty\":\"EC\",\n      \"kid\":\"{k}\",\n      \"crv\":\"P-256\",\n      \"x\":\"{x}\",\n      \"y\":\"{y}\"\n    }}";
        }

        private static string Base64UrlEncode(byte[] input) => Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}