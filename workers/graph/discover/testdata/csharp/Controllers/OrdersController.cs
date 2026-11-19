// Example ASP.NET controller (test fixture for pathos-graph; not built).
using Shop.Services;

namespace Shop.Controllers;

public class OrdersController
{
    private readonly IOrderService _orders;

    public OrdersController(IOrderService orders)
    {
        _orders = orders;
    }

    public string Get(int id)
    {
        var calc = new PriceCalculator();
        return _orders.Describe(id) + calc.Total(id);
    }
}
