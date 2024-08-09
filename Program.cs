namespace RotateJWKS
{
    using System;
    using System.IO;
    using System.Security.Cryptography;

    internal static class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                Environment.FailFast("Usage: RotateJWKS /encryptedDisk/keysFolderPath /toServePublicly/jwks.json");
                return;
            }

            var privateKeysPath = args[0];
            var publicJwksPath = args[1];

            var currentlyPassivePemPath = Path.Combine(privateKeysPath, "currentlyPassive.pem"); // used at the end of this program
            var currentlyActivePemPath = Path.Combine(privateKeysPath, "currentlyActive.pem");

            // first run
            if (!File.Exists(currentlyActivePemPath))
            {
                File.WriteAllText(currentlyActivePemPath, GeneratePEM());
            }

            var currentlyActivePem = File.ReadAllText(currentlyActivePemPath);
            string currentlyActiveJwk = PEMToJWK(currentlyActivePem);

            string newPem = GeneratePEM();
            string newJwk = PEMToJWK(newPem);

            var outputJwks = $"{{\n  \"keys\": [\n{newJwk},\n{currentlyActiveJwk}\n  ]\n}}"; // new key first, then the currently active key that is becoming passive

            // order doesn't matter, because this is to be done in a staging area
            File.WriteAllText(currentlyPassivePemPath, currentlyActivePem);
            File.WriteAllText(currentlyActivePemPath, newPem);
            File.WriteAllText(publicJwksPath, outputJwks);
        }

        private static string GeneratePEM()
        {
            using var rsa = RSA.Create(2048);
            return $"-----BEGIN PRIVATE KEY-----\n{Convert.ToBase64String(rsa.ExportPkcs8PrivateKey())}\n-----END PRIVATE KEY-----";
        }

        private static string PEMToJWK(string pem)
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            var rsaParameters = rsa.ExportParameters(false);

            string k = Base64UrlEncode(SHA256.HashData(rsaParameters.Modulus!));
            string n = Base64UrlEncode(rsaParameters.Modulus!);
            string e = Base64UrlEncode(rsaParameters.Exponent!);
            return $"    {{\n      \"alg\":\"RS256\",\n      \"use\":\"sig\",\n      \"kty\":\"RSA\",\n      \"kid\":\"{k}\",\n      \"e\":\"{e}\",\n      \"n\":\"{n}\"\n    }}";

            static string Base64UrlEncode(byte[] input) => Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
    }
}
