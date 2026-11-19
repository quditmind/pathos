// Example React component (test fixture for pathos-graph; not built).
import { slug } from "../users.service";

export function UserCard({ name }: { name: string }) {
  return <div title={label(name)}>{name}</div>;
}

const label = (name: string) => slug(name);
