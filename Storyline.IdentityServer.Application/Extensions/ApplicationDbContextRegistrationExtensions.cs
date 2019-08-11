using System.Reflection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Storyline.IdentityServer4.Data.Contexts;

namespace Storyline.IdentityServer.Application.Extensions
{
    public static class ApplicationDbContextRegistrationExtensions
    {
        public static IServiceCollection ConfigureIdentityContext(this IServiceCollection services, IConfiguration configuration)
        {
            var contextAssembly = Assembly.GetAssembly(typeof(ApplicationDbContext));
            services.AddDbContext<ApplicationDbContext>(builder =>
                builder.UseSqlServer(configuration.GetConnectionString("Storyline"), sqlOptions => sqlOptions.MigrationsAssembly(contextAssembly.FullName)));

            services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>();
            return services;
        }
    }
}
