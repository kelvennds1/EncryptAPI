using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Reflection.Emit;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Sinqia4Devs.Utils.Cryptography
{
    public static class CustomJWT
    {
        public static string Generate(string tokenId, string issuer, string securityKey, int diasExpiracaoToken, Dictionary<string, string> claims, string audience = null)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(securityKey));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var permClaims = new List<Claim>();
            permClaims.Add(new Claim(JwtRegisteredClaimNames.Jti, tokenId));
            foreach (var claim in claims)
            {
                permClaims.Add(new Claim(claim.Key, claim.Value));
            }

            var token = new JwtSecurityToken(issuer, //Issure    
                            audience ?? issuer,  //Audience    
                            permClaims,
                            expires: DateTime.Now.AddDays(diasExpiracaoToken),
                            signingCredentials: credentials);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public static string GetClaim(string issuer, string securityKey, string token, string claim, string audience = null)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(securityKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            SecurityToken validatedToken;
            var validator = new JwtSecurityTokenHandler();

            TokenValidationParameters validationParameters = new TokenValidationParameters();
            validationParameters.ValidIssuer = issuer;
            validationParameters.ValidAudience = audience ?? issuer;
            validationParameters.IssuerSigningKey = key;
            validationParameters.ValidateIssuerSigningKey = true;
            validationParameters.ValidateAudience = true;

            if (validator.CanReadToken(token))
            {
                ClaimsPrincipal principal;
                try
                {
                    principal = validator.ValidateToken(token, validationParameters, out validatedToken);

                    if (principal.HasClaim(c => c.Type == claim))
                    {
                        return principal.Claims.Where(c => c.Type == claim).First().Value;
                    }
                }
                catch (Exception e)
                {
                    throw e;
                }
            }

            return String.Empty;
        }

        public static Dictionary<string, string> Authenticate(string token, string issuer, string securityKey, string audience = null)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(securityKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            SecurityToken validatedToken;
            var validator = new JwtSecurityTokenHandler();

            TokenValidationParameters validationParameters = new TokenValidationParameters();
            validationParameters.ValidIssuer = issuer;
            validationParameters.ValidAudience = audience ?? issuer;
            validationParameters.IssuerSigningKey = key;
            validationParameters.ValidateIssuerSigningKey = true;
            validationParameters.ValidateAudience = true;

            if (validator.CanReadToken(token))
            {
                ClaimsPrincipal principal;
                try
                {
                    principal = validator.ValidateToken(token, validationParameters, out validatedToken);
                    return principal.Claims.ToDictionary(x => x.Type, x => x.Value);
                }
                catch (Exception e)
                {
                    throw e;
                }
            }

            return null;
        }

    }
}
