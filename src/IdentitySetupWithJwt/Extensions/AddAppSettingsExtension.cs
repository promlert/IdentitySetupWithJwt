using IdentitySetupWithJwt.Configurations;

namespace IdentitySetupWithJwt.Extensions
{
    public static class AddAppSettingsExtension
    {
        public static void AddAppSettings(this IServiceCollection services, IConfiguration configuration)
        {
            services.Configure<JwtConfig>(configuration.GetSection(nameof(JwtConfig)));
            services.Configure<SmtpConfig>(configuration.GetSection(nameof(SmtpConfig)));
        }
    }
}
