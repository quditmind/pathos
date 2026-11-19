const { run } = require("./plugin");

console.log(run(process.env.OP || "escape", process.argv[2] || ""));
