using Authorization.API.Helpers;
using Authorization.API.Models;
using Authorization.API.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Authorization.API.Controllers;

[ApiController]
[Route("admin/clients")]
[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Administrator")]
public class ClientsController : ControllerBase
{
    private readonly IClientService _clients;
    private readonly IClientSecretHasher _secretHasher;

    public ClientsController(IClientService clients, IClientSecretHasher secretHasher)
    {
        _clients = clients;
        _secretHasher = secretHasher;
    }

    [HttpGet]
    public async Task<ActionResult<IEnumerable<ClientResponse>>> List(CancellationToken cancellationToken)
    {
        var clients = await _clients.ListAsync(cancellationToken);
        return Ok(clients.Select(ClientResponse.From));
    }

    [HttpGet("{clientId}")]
    public async Task<ActionResult<ClientResponse>> Get(string clientId)
    {
        var client = await _clients.GetClientById(clientId);
        if (client == null)
        {
            return NotFound();
        }

        return Ok(ClientResponse.From(client));
    }

    [HttpPost]
    public async Task<ActionResult<ClientCreatedResponse>> Create(
        [FromBody] ClientCreateRequest request,
        CancellationToken cancellationToken)
    {
        if (await _clients.GetClientById(request.ClientId) != null)
        {
            return Conflict(new { error = "client_id already exists." });
        }

        var plaintextSecret = request.RequireClientSecret
            ? (string.IsNullOrWhiteSpace(request.ClientSecret)
                ? TokenHelper.GenerateSecureCode(32)
                : request.ClientSecret)
            : null;

        var client = new Client
        {
            ClientId = request.ClientId,
            Description = request.Description,
            ClientSecret = plaintextSecret == null ? null : _secretHasher.Hash(plaintextSecret),
            RedirectUri = request.RedirectUri,
            PostLogoutRedirectUri = request.PostLogoutRedirectUri,
            RequirePkce = request.RequireClientSecret ? request.RequirePkce : true,
            RequireClientSecret = request.RequireClientSecret,
            RequireConsent = request.RequireConsent,
            AllowRefreshToken = request.AllowRefreshToken,
            AllowedScopes = request.AllowedScopes
        };

        await _clients.CreateAsync(client, cancellationToken);

        var response = new ClientCreatedResponse
        {
            ClientId = client.ClientId,
            Description = client.Description,
            RedirectUri = client.RedirectUri,
            PostLogoutRedirectUri = client.PostLogoutRedirectUri,
            RequirePkce = client.RequirePkce,
            RequireClientSecret = client.RequireClientSecret,
            RequireConsent = client.RequireConsent,
            AllowRefreshToken = client.AllowRefreshToken,
            AllowedScopes = client.AllowedScopes.ToList(),
            ClientSecret = plaintextSecret
        };

        return CreatedAtAction(nameof(Get), new { clientId = client.ClientId }, response);
    }

    [HttpPut("{clientId}")]
    public async Task<ActionResult<ClientResponse>> Update(
        string clientId,
        [FromBody] ClientUpdateRequest request,
        CancellationToken cancellationToken)
    {
        var client = await _clients.GetClientById(clientId);
        if (client == null)
        {
            return NotFound();
        }

        if (request.Description != null)
        {
            client.Description = request.Description;
        }

        if (request.RedirectUri != null)
        {
            client.RedirectUri = request.RedirectUri;
        }

        if (request.PostLogoutRedirectUri != null)
        {
            client.PostLogoutRedirectUri = request.PostLogoutRedirectUri;
        }

        if (request.RequirePkce.HasValue)
        {
            client.RequirePkce = request.RequirePkce.Value;
        }

        if (request.RequireClientSecret.HasValue)
        {
            client.RequireClientSecret = request.RequireClientSecret.Value;
            if (!client.RequireClientSecret)
            {
                client.RequirePkce = true;
                client.ClientSecret = null;
            }
        }

        if (request.RequireConsent.HasValue)
        {
            client.RequireConsent = request.RequireConsent.Value;
        }

        if (request.AllowRefreshToken.HasValue)
        {
            client.AllowRefreshToken = request.AllowRefreshToken.Value;
        }

        if (request.AllowedScopes != null)
        {
            client.AllowedScopes = request.AllowedScopes;
        }

        await _clients.UpdateAsync(client, cancellationToken);
        return Ok(ClientResponse.From(client));
    }

    [HttpPost("{clientId}/secret")]
    public async Task<ActionResult<ClientCreatedResponse>> RotateSecret(
        string clientId,
        CancellationToken cancellationToken)
    {
        var client = await _clients.GetClientById(clientId);
        if (client == null)
        {
            return NotFound();
        }

        if (!client.RequireClientSecret)
        {
            return BadRequest(new { error = "public_client", error_description = "Public clients do not have a secret." });
        }

        var plaintextSecret = TokenHelper.GenerateSecureCode(32);
        client.ClientSecret = _secretHasher.Hash(plaintextSecret);
        await _clients.UpdateAsync(client, cancellationToken);

        var response = ClientResponse.From(client);
        return Ok(new ClientCreatedResponse
        {
            ClientId = response.ClientId,
            Description = response.Description,
            RedirectUri = response.RedirectUri,
            PostLogoutRedirectUri = response.PostLogoutRedirectUri,
            RequirePkce = response.RequirePkce,
            RequireClientSecret = response.RequireClientSecret,
            RequireConsent = response.RequireConsent,
            AllowRefreshToken = response.AllowRefreshToken,
            AllowedScopes = response.AllowedScopes,
            ClientSecret = plaintextSecret
        });
    }

    [HttpDelete("{clientId}")]
    public async Task<IActionResult> Delete(string clientId, CancellationToken cancellationToken)
    {
        var client = await _clients.GetClientById(clientId);
        if (client == null)
        {
            return NotFound();
        }

        await _clients.DeleteAsync(client, cancellationToken);
        return NoContent();
    }
}
