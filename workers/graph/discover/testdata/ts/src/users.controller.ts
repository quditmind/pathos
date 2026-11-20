// Example NestJS controller (test fixture for pathos-graph; not built).
import { UsersService, slug as toSlug } from "./users.service";

export class UsersController {
  constructor(private readonly users: UsersService) {}

  get(id: string): string {
    return toSlug(this.users.find(id));
  }
}
