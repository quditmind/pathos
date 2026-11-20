// Example services (test fixture for pathos-graph; not built).
namespace Shop.Services;

public interface IOrderService
{
    string Describe(int id);
}

public class PriceCalculator
{
    public decimal Total(int id) { return Round(id * 1.2m); }
    private decimal Round(decimal v) { return decimal.Round(v, 2); }
}
