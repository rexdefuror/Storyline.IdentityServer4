using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using System.IO;

namespace Storyline.IdentityServer4.Data.Factories
{
    public class ConfigurationDbContextDesignTimeFactory : IDesignTimeDbContextFactory<ConfigurationDbContext>
    {
        public ConfigurationDbContext CreateDbContext(string[] args)
        {
            IConfigurationRoot configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("dataSettings.json")
                .Build();

            var builder = new DbContextOptionsBuilder<ConfigurationDbContext>();
            var connectionString = configuration.GetConnectionString("Storyline");
            builder.UseSqlServer(connectionString, b => b.MigrationsAssembly("Storyline.IdentityServer4.Data"));

            return new ConfigurationDbContext(builder.Options, new ConfigurationStoreOptions
            {
                ConfigureDbContext = b => b.UseSqlServer(connectionString)
            });
        }
    }
}
