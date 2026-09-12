using ApplicationLayer;
using CoreModels;
using Microsoft.AspNetCore.Mvc;
namespace AzureGuard.Controllers; [ApiController][Route("api/auth")] public class AuthController(AuthService auth) : ControllerBase { [HttpPost("signup")] public async Task<IActionResult> Signup(SignupRequest r) { if (r.Password.Length < 8) return BadRequest("Password must contain at least 8 characters."); var x = await auth.Signup(r); return x is null ? Conflict("Email already exists.") : Ok(x); } [HttpPost("login")] public async Task<IActionResult> Login(LoginRequest r) { var x = await auth.Login(r); return x is null ? Unauthorized("Invalid credentials.") : Ok(x); } }
