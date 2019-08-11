using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using Storyline.IdentityServer4.Data.Contexts;
using System.IO;

namespace Storyline.IdentityServer4.Data.Factories
{
    public class ApplicationDbContextDesignTimeFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
    {
        public ApplicationDbContext CreateDbContext(string[] args)
        {
            IConfigurationRoot configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("dataSettings.json")
                .Build();

            var builder = new DbContextOptionsBuilder<ApplicationDbContext>();
            var connectionString = configuration.GetConnectionString("Storyline");
            builder.UseSqlServer(connectionString, b => b.MigrationsAssembly("Storyline.IdentityServer4.Data"));

            return new ApplicationDbContext(builder.Options);
        }
    }
}
