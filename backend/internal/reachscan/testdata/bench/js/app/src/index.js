const _ = require("lodash");
const { renderGreeting } = require("./views");

function main(argv) {
  const names = _.uniq(argv.slice(2));
  // lodash.zipObjectDeep (prototype pollution) is never called.
  for (const n of names) {
    console.log(renderGreeting(n));
  }
}

main(process.argv);
