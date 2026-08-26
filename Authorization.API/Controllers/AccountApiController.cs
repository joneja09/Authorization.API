using System.Security.Claims;
using Authorization.API.Models;
using Authorization.API.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Authorization.API.Controllers;

[ApiController]
[Route("account")]
public class AccountApiController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ITokenService _tokenService;
    private readonly IClientService _clientService;

    public AccountApiController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ITokenService tokenService,
        IClientService clientService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenService = tokenService;
        _clientService = clientService;
    }

    [HttpPost("login/token")]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> LoginToken([FromBody] LoginModel model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            return Unauthorized("Invalid email or password.");
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: true);
        if (!result.Succeeded)
        {
            if (result.IsLockedOut)
            {
                return StatusCode(StatusCodes.Status403Forbidden, "User account is locked out. Try again later.");
            }

            return Unauthorized("Invalid email or password.");
        }

        var accessToken = _tokenService.GenerateJwtToken(user, await _userManager.GetRolesAsync(user));
        var refreshToken = _tokenService.GenerateRefreshToken();
        await _tokenService.StoreRefreshToken(refreshToken, user.Id);

        return Ok(new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            TokenType = "Bearer",
            ExpiresIn = _tokenService.GetAccessTokenExpirySeconds()
        });
    }

    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
        {
            return Unauthorized("User not found.");
        }

        await _tokenService.RevokeUserRefreshTokens(userId);
        await _signInManager.SignOutAsync();

        return Ok(new { message = "Logged out successfully" });
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        var user = new ApplicationUser { UserName = model.Username, Email = model.Email };
        var result = await _userManager.CreateAsync(user, model.Password);

        if (!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }

        return Ok(new { message = "User registered successfully" });
    }

    [HttpPost("refresh")]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest model)
    {
        if (string.IsNullOrWhiteSpace(model.UserId) && string.IsNullOrWhiteSpace(model.ClientId))
        {
            return BadRequest("User ID or Client ID is required.");
        }

        if (string.IsNullOrWhiteSpace(model.RefreshToken))
        {
            return BadRequest("Refresh token is required.");
        }

        ApplicationUser? user = null;
        if (!string.IsNullOrWhiteSpace(model.UserId))
        {
            user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
            {
                return BadRequest("User is not valid.");
            }
        }

        Client? client = null;
        if (!string.IsNullOrWhiteSpace(model.ClientId))
        {
            client = await _clientService.GetClientById(model.ClientId);
            if (client == null)
            {
                return Unauthorized("Client is not valid.");
            }
        }

        var tokenIsValid = await _tokenService.ValidateRefreshToken(model.RefreshToken, model.UserId, model.ClientId);
        if (!tokenIsValid)
        {
            return Unauthorized("Invalid refresh token.");
        }

        await _tokenService.RevokeRefreshToken(model.RefreshToken, model.UserId, model.ClientId);

        var newAccessToken = user == null
            ? _tokenService.GenerateJwtToken(client!)
            : _tokenService.GenerateJwtToken(user, await _userManager.GetRolesAsync(user));
        var newRefreshToken = _tokenService.GenerateRefreshToken();

        await _tokenService.StoreRefreshToken(newRefreshToken, user?.Id, client?.ClientId);

        return Ok(new TokenResponse
        {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken,
            TokenType = "Bearer",
            ExpiresIn = _tokenService.GetAccessTokenExpirySeconds()
        });
    }

    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [HttpGet("me")]
    public async Task<IActionResult> GetUserInfo()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound("User not found.");
        }

        return Ok(new
        {
            id = user.Id,
            username = user.UserName,
            email = user.Email
        });
    }
}
