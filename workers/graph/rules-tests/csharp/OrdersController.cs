// Test fixture for the PATHOS graph rules (example code, not executed).
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Shop.Web;

// ruleid: pathos-graph-csharp-route-prefix
[Route("api/orders")]
public class OrdersController : ControllerBase
{
    private readonly ShopContext _db;

    // ruleid: pathos-graph-csharp-route-attribute
    [HttpGet("{id}")]
    public IActionResult Get(int id)
    {
        // ruleid: pathos-graph-csharp-db-ef
        var o = _db.Orders.Find(id);
        return Ok(o);
    }

    // ruleid: pathos-graph-csharp-route-attribute
    [HttpPost]
    public async Task<IActionResult> Create(Order o)
    {
        // ruleid: pathos-graph-csharp-db-ef
        _db.Orders.Add(o);
        // ruleid: pathos-graph-csharp-db-ef
        await _db.SaveChangesAsync();
        // ruleid: pathos-graph-csharp-http-call
        await _http.PostAsync("https://api.tax.example.net/v2/quote", null);
        return Ok();
    }
}

public static class Endpoints
{
    public static void Map(WebApplication app)
    {
        // ruleid: pathos-graph-csharp-route-minimal
        app.MapGet("/health", Health);
        // ruleid: pathos-graph-csharp-db-sql-read
        var cmd = new SqlCommand("SELECT count(*) FROM orders", conn);
    }
}
