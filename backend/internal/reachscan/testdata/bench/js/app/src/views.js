import { compile, capitalize } from "./util/strings";

// Reachable: lodash.template, through the re-export in util/strings.js.
export function renderGreeting(name) {
  const tpl = compile("Hello <%= who %>");
  return tpl({ who: capitalize(name) });
}
