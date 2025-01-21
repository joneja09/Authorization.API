using Authorization.API.Models;
using Authorization.API.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Authorization.API.Controllers;

[Route("account")]
public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IConfiguration _config;
    private readonly TokenService _tokenService;
    private readonly IClientService _clientService;

    public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IConfiguration config, TokenService tokenService, IClientService clientService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _config = config;
        _tokenService = tokenService;
        _clientService = clientService;
    }

    /// <summary>
    /// Displays the login page.
    /// </summary>
    [HttpGet("login")]
    public IActionResult Login(string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        return View(); // Returns a Razor View (if applicable)
    }

    /// <summary>
    /// Handles user login and sets authentication cookies.
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
            return Unauthorized("Invalid email or password");

        var result = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, lockoutOnFailure: true);

        if (!result.Succeeded)
        {
            if (result.IsLockedOut)
                return Forbid("User account is locked out. Try again later.");
            if (result.RequiresTwoFactor)
                return Unauthorized("Two-factor authentication is required.");
            return Unauthorized("Invalid email or password.");
        }

        // Use TokenService to generate JWT
        var token = _tokenService.GenerateJwtToken(user);
        var refreshToken = _tokenService.GenerateRefreshToken();

        return Ok(new
        {
            access_token = token,
            refresh_token = refreshToken,
            token_type = "Bearer",
            expires_in = 3600
        });
    }

    /// <summary>
    /// Logs out the user and removes authentication cookies.
    /// </summary>
    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId == null)
            return Unauthorized("User not found");

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return Unauthorized("Invalid user");

        // Revoke refresh token
        await _tokenService.RevokeUserRefreshTokens(user.Id);

        // Sign out the user (for cookie-based auth)
        await _signInManager.SignOutAsync();

        return Ok(new { message = "Logged out successfully" });
    }

    /// <summary>
    /// Registers a new user.
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = new ApplicationUser { UserName = model.Username, Email = model.Email };
        var result = await _userManager.CreateAsync(user, model.Password);

        if (!result.Succeeded)
            return BadRequest(result.Errors);

        return Ok("User registered successfully");
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest model)
    {
        if (string.IsNullOrWhiteSpace(model.UserId) && string.IsNullOrWhiteSpace(model.ClientId))
        {
            return BadRequest("User ID or Client ID is required");
        }

        if (string.IsNullOrWhiteSpace(model.RefreshToken))
        {
            return BadRequest("Refresh token is required");
        }

        ApplicationUser? user = null;
        if (!string.IsNullOrWhiteSpace(model.UserId))
        {
            user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
                return BadRequest("User is not valid.");
        }

        Client? client = null;
        if (!string.IsNullOrWhiteSpace(model.ClientId))
        {
            client = await _clientService.GetClientById(model.ClientId!);
            if (client == null)
                return Unauthorized("Client is not valid.");
        }

        var tokenIsValid = await _tokenService.ValidateRefreshToken(model.RefreshToken, model.UserId, model.ClientId);

        if (!tokenIsValid)
        {
            return Unauthorized("Invalid refresh token");
        }

        var newAccessToken = user == null ? _tokenService.GenerateJwtToken(client!) : _tokenService.GenerateJwtToken(user);
        var newRefreshToken = _tokenService.GenerateRefreshToken();

        await _tokenService.StoreRefreshToken(newRefreshToken, user?.Id, client?.ClientId);

        return Ok(new
        {
            access_token = newAccessToken,
            refresh_token = newRefreshToken,
            token_type = "Bearer",
            expires_in = 3600
        });
    }

    /// <summary>
    /// Gets the currently logged-in user's information.
    /// </summary>
    [Authorize]
    [HttpGet("me")]
    public async Task<IActionResult> GetUserInfo()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return NotFound("User not found");

        return Ok(new
        {
            id = user.Id,
            username = user.UserName,
            email = user.Email
        });
    }
}
