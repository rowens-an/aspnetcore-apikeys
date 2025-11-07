using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models;

namespace ExampleAPI;

public class Startup(IConfiguration configuration)
{
    public IConfiguration Configuration { get; } = configuration;

    // This method gets called by the runtime. Use this method to add services to the container.
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddControllers();

        services.AddSwaggerGen(c =>
        {
            c.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "ExampleAPI",
                Version = "1.0"
            });

            var basicScheme = new OpenApiSecurityScheme
            {                    
                Type = SecuritySchemeType.Http,
                Scheme = "Basic",
                In =  ParameterLocation.Header,
                Description = "Username is ClientID, password is key.",
                Reference = new OpenApiReference
                {
                    Id = "Basic",
                    Type = ReferenceType.SecurityScheme
                }
            };

            c.AddSecurityDefinition(basicScheme.Reference.Id, basicScheme);
            c.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                { basicScheme, new string[]{ } }
            });
        });

        services.Configure<Csg.AspNetCore.Authentication.ApiKey.ConfigurationApiKeyStoreOptions>(Configuration.GetSection("ApiKeys"));

        services.AddConfigurationApiKeyStore();

        services.AddAuthentication(Csg.AspNetCore.Authentication.ApiKey.ApiKeyDefaults.Name)
            .AddApiKey(conf => {
                conf.StaticKeyEnabled = true;
                conf.HttpBasicEnabled = true;
                conf.TimeBasedKeyEnabled = true;
                    
                conf.HeaderName = "HeaderName";
                conf.HeaderName = null;
                conf.QueryString = "param_name";
                conf.QueryString = null;
            });

        services.AddMvc();
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        app.UseRouting();

        app.UseAuthentication();

        app.UseAuthorization();

        app.UseSwagger();

        app.UseSwaggerUI(c =>
        {
            c.SwaggerEndpoint("/swagger/v1/swagger.json", "ExampleAPI V1");
        });

        app.UseEndpoints(ep =>
        {
            ep.MapControllers();
        });
    }
}