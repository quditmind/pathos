// Example NestJS service (test fixture for pathos-graph; not built).
export class UsersService {
  find(id: string): string {
    return this.normalise(id);
  }

  private normalise(id: string): string {
    return id.trim();
  }
}

export function slug(s: string): string {
  return s.toLowerCase();
}
