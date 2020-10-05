using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Claims;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;

namespace JWT
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine(Sign());
            Console.ReadLine();
        }

        static string Sign()
        {

            string audience = "https://appleid.apple.com";
            string issuer = ""; //team 
            string subject = ""; //service identifier
            string kid = ""; //service key
            string p8key = ""; //key

            IList<Claim> claims = new List<Claim> {
                                new Claim ("sub", subject)
            };

            CngKey cngKey = CngKey.Import(Convert.FromBase64String(p8key), CngKeyBlobFormat.Pkcs8PrivateBlob);

            SigningCredentials signingCred = new SigningCredentials(
                new ECDsaSecurityKey(new ECDsaCng(cngKey)),
                SecurityAlgorithms.EcdsaSha256
            );

            JwtSecurityToken token = new JwtSecurityToken(
                issuer,
                audience,
                claims,
                DateTime.Now,
                DateTime.Now.AddDays(180),
                signingCred
            );
            token.Header.Add("kid", kid);
            token.Header.Remove("typ");

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            string jwt = tokenHandler.WriteToken(token);
            return jwt;
        }
    }
}