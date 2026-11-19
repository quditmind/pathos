const u = require("underscore");

// Dynamic dispatch: the underscore function is chosen at run time by name,
// so the analysis cannot tell whether underscore.template is called.
function run(op, input) {
  const fn = u[op];
  return fn(input);
}

module.exports = { run };
