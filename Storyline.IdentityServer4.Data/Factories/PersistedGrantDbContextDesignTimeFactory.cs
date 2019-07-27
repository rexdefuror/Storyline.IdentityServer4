using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using System.IO;

namespace Storyline.IdentityServer4.Data.Factories
{
    public class PersistedGrantDbContextDesignTimeFactory : IDesignTimeDbContextFactory<PersistedGrantDbContext>
    {
        public PersistedGrantDbContext CreateDbContext(string[] args)
        {
            IConfigurationRoot configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("dataSettings.json")
                .Build();

            var builder = new DbContextOptionsBuilder<PersistedGrantDbContext>();
            var connectionString = configuration.GetConnectionString("Storyline");
            builder.UseSqlServer(connectionString, b => b.MigrationsAssembly("Storyline.IdentityServer4.Data"));

            return new PersistedGrantDbContext(builder.Options, new OperationalStoreOptions
            {
                ConfigureDbContext = b => b.UseSqlServer(connectionString),
                EnableTokenCleanup = true,
                TokenCleanupInterval = 30
            });
        }
    }
}
