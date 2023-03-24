using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(option =>
    {
        builder.Configuration.Bind("AzureAd", option);

        option.Scope.Add("offline_access");

        option.ResponseType = OpenIdConnectResponseType.CodeIdToken;

        option.Events = new OpenIdConnectEvents()
        {
            OnAuthorizationCodeReceived = async (context) =>
            {
                if (string.IsNullOrEmpty(context.TokenEndpointRequest.ClientSecret))
                {
                     context.TokenEndpointRequest.ClientSecret = builder.Configuration.GetSection("AzureAd:ClientSecret").Value;
                }

                await Task.CompletedTask.ConfigureAwait(false);
            },
            OnTokenResponseReceived = async (context) =>
            {
                var AccessToken = context.TokenEndpointResponse.AccessToken;
                var RefreshToken = context.TokenEndpointResponse.RefreshToken;
                var IdToken = context.TokenEndpointResponse.IdToken;
                var ExpiresIn = context.TokenEndpointResponse.ExpiresIn;

                await Task.CompletedTask.ConfigureAwait(false);
            }
        };
    });



builder.Services.AddControllersWithViews(options =>
{
    var policy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
    options.Filters.Add(new AuthorizeFilter(policy));
});
builder.Services.AddRazorPages();
    

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();
