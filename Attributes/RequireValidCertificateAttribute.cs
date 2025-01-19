using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using LeopardApp.Services.Interfaces;

namespace LeopardApp.Attributes;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class RequireValidCertificateAttribute : Attribute, IAsyncAuthorizationFilter
{
    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var userService = context.HttpContext.RequestServices.GetRequiredService<IUserService>();
        var email = context.HttpContext.User.FindFirstValue(ClaimTypes.Email);

        if (string.IsNullOrEmpty(email))
        {
            context.Result = new RedirectToActionResult("Login", "Account", null);
            return;
        }

        var user = await userService.GetUserByEmailAsync(email);

        // Check if certificate is validated in session
        var certificateValidated = context.HttpContext.Session.GetString("CertificateValidated");

        if (user == null || !user.CertificateDownloaded || certificateValidated != "true")
        {
            context.Result = new RedirectToActionResult("VerifyCertificate", "User", null);
            return;
        }
    }
}