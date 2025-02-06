using IdentitySetupWithJwt.Services;
using IdentitySetupWithJwt.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentitySetupWithJwt.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class AccountController(IAccountService accountService) : ControllerBase
    {
        [HttpGet]
        [Authorize]
        public IActionResult GetDetails()
        {
            var user = HttpContext.User.Identity?.Name;
            return Ok(new { message = $"Your Email/UserName Is {user}" });
        }
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> GetRefreshToken(string accessToken, string refreshToken) =>
            (await accountService.RefreshTokenAsync(accessToken, refreshToken))
            .Match(
                l => Problem(detail: l, statusCode: StatusCodes.Status401Unauthorized),
                Ok
            );

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginVM loginVM)
        {
            var result = await accountService.LoginAsync(loginVM);
            return result.Match(
                l => Problem(detail: l, statusCode: StatusCodes.Status401Unauthorized),
                Ok
            );
        }
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Register(RegisterVM registerVM)
        {
            var result = await accountService.RegisterAsync(registerVM);
            return result.Match(
                l => Problem(detail: l, statusCode: StatusCodes.Status400BadRequest),
                Ok
            );
        }
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string email, string emailToken)
        {
            var result = await accountService.ConfirmEmailAsync(email, emailToken);
            return result.Match(
                l => Problem(detail: l, statusCode: StatusCodes.Status400BadRequest),
                r => Ok(new { message = "Email Confirmed" })
                );
        }
    }
}
