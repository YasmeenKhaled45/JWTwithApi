using JWTRefreshTokenInDotNet6.Helpers;
using JWTRefreshTokenInDotNet6.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTRefreshTokenInDotNet6.Services
{
    public class AuthServices : IAuthService
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly JWT jWT;
        public AuthServices(UserManager<ApplicationUser> userManager, JWT jWT)
        {
            this.userManager = userManager;
            this.jWT = jWT;
        }

        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
            if (await userManager.FindByEmailAsync(model.Email) is not null)
                return new AuthModel { Message= "Email is already registered!" };

            if (await userManager.FindByNameAsync(model.Username) is not null)
                return new AuthModel { Message = "UserName is already registerd!" };

            var user = new ApplicationUser
            {
                FirstName = model.Username,
                LastName = model.LastName,
                Email = model.Email,
                UserName = model.Username,
            };
           var res = await userManager.CreateAsync(user , model.Password);
            if (!res.Succeeded)
            {
                var errors = string.Empty;
                foreach (var error in res.Errors)
                    errors += $"{error.Description},";


                return new AuthModel { Message = errors };

            }

            await userManager.AddToRoleAsync(user , "User");
            var jwtSecurityToken = await CreateJwtToken(user);

            return new AuthModel
            {
                Email = user.Email,
                ExpiresOn = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                Username = user.UserName
            };


        }
        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await userManager.GetClaimsAsync(user);
            var roles = await userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jWT.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: jWT.Issuer,
                audience: jWT.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(jWT.DurationInDays),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }
        public Task<string> AddRoleAsync(AddRoleModel model)
        {
            throw new NotImplementedException();
        }

        public Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {
            throw new NotImplementedException();
        }

       
    }
}
