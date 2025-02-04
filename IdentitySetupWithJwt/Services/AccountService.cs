using System.IdentityModel.Tokens.Jwt;
using System.Net.Mail;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using IdentitySetupWithJwt.Configurations;
using IdentitySetupWithJwt.Models;
using IdentitySetupWithJwt.Utilities;
using IdentitySetupWithJwt.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace IdentitySetupWithJwt.Services;

public interface IAccountService
{
    Task<MethodResult<bool>> ConfirmEmailAsync(string email, string emailToken);
    Task<MethodResult<JwtTokenResponseVM>> LoginAsync(LoginVM loginVm);
    Task<MethodResult<JwtTokenResponseVM>> RefreshTokenAsync(string accessToken, string refreshToken);
    Task<MethodResult<RegisterVM>> RegisterAsync(RegisterVM registerVm);
}

public class AccountService : IAccountService
{
    private readonly JwtConfig _jwtConfig;
    private readonly SymmetricSecurityKey _key;
    private readonly UserManager<AppUser> _userManager;
    private readonly SignInManager<AppUser> _signInManager;
    private readonly SmtpConfig _smtpConfig;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AccountService(
        IOptions<JwtConfig> jwtConfigOptions,
        UserManager<AppUser> userManager,
        SignInManager<AppUser> signInManager,
        IOptions<SmtpConfig> smtpConfigOptions,
        IHttpContextAccessor httpContextAccessor)
    {
        _jwtConfig = jwtConfigOptions.Value;
        _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfig.SecretKey));
        _userManager = userManager;
        _signInManager = signInManager;
        _smtpConfig = smtpConfigOptions.Value;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<MethodResult<JwtTokenResponseVM>> LoginAsync(LoginVM loginVm)
    {
        var user = await _userManager.FindByEmailAsync(loginVm.Email);
        if (user == null)
        {
            return new MethodResult<JwtTokenResponseVM>.Failure("Invalid Email Or Password");
        }
        var result = await _signInManager.CheckPasswordSignInAsync(user, loginVm.Password, false);
        if (result.IsNotAllowed)
        {
            return new MethodResult<JwtTokenResponseVM>.Failure("Email Not Confirmed");
        }
        if (!result.Succeeded)
        {
            return new MethodResult<JwtTokenResponseVM>.Failure("Invalid Email Or Password");
        }
        var roles = (await _userManager.GetRolesAsync(user)).ToList();
        var claims = new List<Claim>
        {
            new(ClaimTypes.Email, user.Email??""),
            new(ClaimTypes.Role, string.Join(',',roles)),
            new(ClaimTypes.Name, user.UserName ?? ""),
            new(ClaimTypes.NameIdentifier, user.Id),
        };

        return await CreateTokenAsync(claims, user);
    }

    public async Task<MethodResult<RegisterVM>> RegisterAsync(RegisterVM registerVm)
    {
        var user = new AppUser
        {
            Email = registerVm.Email,
            UserName = registerVm.Email,
            FullName = registerVm.FullName,
            EmailConfirmed = false,
            LockoutEnabled = false
        };
        var result = await _userManager.CreateAsync(user, registerVm.Password);
        if (!result.Succeeded)
        {
            return new MethodResult<RegisterVM>.Failure(string.Join(',', result.Errors.Select(e => e.Description)));
        }
        var resultRoleCreation = await _userManager.AddToRoleAsync(user, ApplicationConstants.RolesTypes.User);
        if (!resultRoleCreation.Succeeded)
        {
            return new MethodResult<RegisterVM>.Failure(string.Join(',', resultRoleCreation.Errors.Select(e => e.Description)));
        }
        await SendVerificationEmail(user);
        return new MethodResult<RegisterVM>.Success(registerVm);
    }

    public async Task<MethodResult<JwtTokenResponseVM>> RefreshTokenAsync(string accessToken, string refreshToken) =>
        await GetPrincipalFromExpiredToken(accessToken).Bind(
            r => GetToken(refreshToken, r)
        );

    public async Task<MethodResult<bool>> ConfirmEmailAsync(string email, string emailToken)
    {
        AppUser? user = await _userManager.FindByEmailAsync(email);
        if (user != null)
        {
            var result = await _userManager.ConfirmEmailAsync(user, emailToken);
            if (!result.Succeeded)
            {
                return new MethodResult<bool>.Failure(string.Join(',', result.Errors.Select(e => e.Description)));
            }
            return new MethodResult<bool>.Success(true);
        }
        return new MethodResult<bool>.Failure("Error While Confirming Email");
    }

    private async Task<MethodResult<JwtTokenResponseVM>> GetToken(string refreshToken, ClaimsPrincipal result)
    {
        var userId = result.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
        {
            return new MethodResult<JwtTokenResponseVM>.Failure("Invalid Access Token");
        }
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null || user.RefreshToken != refreshToken)
        {
            return new MethodResult<JwtTokenResponseVM>.Failure("Invalid Refresh Token");
        }
        if (user.RefreshTokenExpiryTime <= DateTime.UtcNow)
        {
            return new MethodResult<JwtTokenResponseVM>.Failure("Refresh Token Expired");
        }
        var claims = result.Claims;
        return await CreateTokenAsync(claims, user);
    }

    private async Task<MethodResult<JwtTokenResponseVM>> CreateTokenAsync(IEnumerable<Claim> claims, AppUser user)
    {
        var newAccessToken = GenerateAccessToken(claims);
        var newRefreshToken = GenerateRefreshToken();

        user.RefreshToken = newRefreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(_jwtConfig.RefreshTokenValidityDays);
        var result = await _userManager.UpdateAsync(user);

        if (!result.Succeeded)
        {
            return new MethodResult<JwtTokenResponseVM>.Failure("Failed To Update Refresh Token");
        }

        var refreshTokenExpiryTimeStamp = DateTime.UtcNow.AddDays(_jwtConfig.RefreshTokenValidityDays);
        var accessTokenExpiryTimeStamp = DateTime.UtcNow.AddMinutes(_jwtConfig.AccessTokenValidityMin);

        return new MethodResult<JwtTokenResponseVM>.Success(new JwtTokenResponseVM
        {
            AccessToken = newAccessToken,
            AccessTokenExpiresIn = (int)accessTokenExpiryTimeStamp.Subtract(DateTime.UtcNow).TotalSeconds,
            RefreshToken = newRefreshToken,
            RefreshTokenExpiresIn = (int)refreshTokenExpiryTimeStamp.Subtract(DateTime.UtcNow).TotalSeconds
        });
    }

    private MethodResult<ClaimsPrincipal> GetPrincipalFromExpiredToken(string accessToken)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = true,
            ValidAudience = _jwtConfig.Audience,
            ValidateIssuer = true,
            ValidIssuer = _jwtConfig.Issuer,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.Zero,
            IssuerSigningKey = _key,
            ValidateLifetime = false //here we are saying that we don't care about the token's expiration date
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out var securityToken);
        if (securityToken is not JwtSecurityToken jwtSecurityToken)
        {
            return new MethodResult<ClaimsPrincipal>.Failure("Invalid Token");
        }

        if (!jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha512, StringComparison.InvariantCultureIgnoreCase))
            return new MethodResult<ClaimsPrincipal>.Failure("Invalid Token");
        return new MethodResult<ClaimsPrincipal>.Success(principal);
    }

    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }

    private string GenerateAccessToken(IEnumerable<Claim> claims)
    {
        var creds = new SigningCredentials(_key, SecurityAlgorithms.HmacSha512Signature);
        var tokenExpiryTimeStamp = DateTime.UtcNow.AddMinutes(_jwtConfig.AccessTokenValidityMin);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = tokenExpiryTimeStamp,
            SigningCredentials = creds,
            Issuer = _jwtConfig.Issuer,
            Audience = _jwtConfig.Audience
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var accessToken = tokenHandler.WriteToken(token);
        return accessToken;
    }

    private async Task<bool> SendVerificationEmail(AppUser user)
    {
        var url = _httpContextAccessor.HttpContext?.Request.Host;
        var emailToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var passwordToken = await _userManager.GeneratePasswordResetTokenAsync(user);
        var verificationUrl = $"https://{url}/api/Account/ConfirmEmail?email={Uri.EscapeDataString(user.Email!)}&emailToken={Uri.EscapeDataString(emailToken)}";
        using (MailMessage mail = new MailMessage())
        {
            mail.From = new MailAddress(ApplicationConstants.AdminAccount.Email);
            mail.To.Add(user.Email!);
            mail.Subject = "Activate Your Account";
            mail.Body = $"<h4>Please click the following link to activate your account: <a href='{verificationUrl}'>Verify Me</a></h4>";
            mail.IsBodyHtml = true;
            using (SmtpClient smtp = new SmtpClient(_smtpConfig.Host, _smtpConfig.Port))
            {
                smtp.UseDefaultCredentials = false;
                smtp.Credentials = new NetworkCredential(_smtpConfig.UserName, _smtpConfig.Password);
                smtp.EnableSsl = true;
                await smtp.SendMailAsync(mail);
            }
        }
        return true;
    }
}