using Microsoft.AspNetCore.Mvc;

namespace Storyline.Client.Controllers
{
    public class LogoutController : Controller
    {
        public IActionResult Index()
        {
            return RedirectToAction("Index", "Home");
        }

        public IActionResult Logout()
        {
            return new SignOutResult(new[] { "Cookies", "oidc" });
        }
    }
}