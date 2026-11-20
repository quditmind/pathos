// Test fixture for the PATHOS graph rules (example code, not executed).
import { Controller, Get, Post } from "@nestjs/common";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

// ruleid: pathos-graph-js-route-prefix-nest
@Controller("users")
export class UsersController {
  // ruleid: pathos-graph-js-route-nest
  @Get(":id")
  find(id: string) {
    // ruleid: pathos-graph-js-db-prisma
    return prisma.user.findUnique({ where: { id } });
  }

  // ruleid: pathos-graph-js-route-nest
  @Post()
  create() {
    // ruleid: pathos-graph-js-db-prisma
    return prisma.user.create({ data: {} });
  }
}
