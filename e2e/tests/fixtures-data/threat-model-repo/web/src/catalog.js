// Catalogue client (test fixture for pathos-graph).
async function listProducts() {
  const r = await fetch("https://cdn.partner-api.net/catalog.json");
  return normalise(await r.json());
}

function normalise(items) {
  return items.map((i) => ({ id: i.id, name: i.name }));
}

module.exports = { listProducts };
