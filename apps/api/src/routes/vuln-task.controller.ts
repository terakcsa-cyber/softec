import { Body, Controller, Get, Param, Patch, Post, Query } from "@nestjs/common";
import { VulnTaskService, type VulnTaskPriorityLocal, type VulnTaskStatus } from "../services/vuln-task.service.js";

@Controller("vuln-tasks")
export class VulnTaskController {
  constructor(private readonly tasks: VulnTaskService) {}

  @Get()
  async list(
    @Query("q") q?: string,
    @Query("status") status?: string,
    @Query("limit") limit?: string,
    @Query("sort") sort?: string
  ) {
    return this.tasks.list({ q, status, limit: limit ? Number(limit) : undefined, sort });
  }

  @Post()
  async create(
    @Body()
    body: {
      title?: string;
      vendorKey: string;
      vendorDisplay: string;
      productKeyNorm?: string | null;
      productDisplay?: string | null;
      owner?: string | null;
      dueDate?: string | null;
      priorityLocal?: VulnTaskPriorityLocal;
      cveIds?: string[];
      notesMd?: string | null;
    }
  ) {
    return this.tasks.create(body);
  }

  @Get(":id")
  async get(@Param("id") id: string) {
    return this.tasks.get(id);
  }

  @Patch(":id")
  async patch(
    @Param("id") id: string,
    @Body()
    body: Partial<{
      title: string;
      status: VulnTaskStatus;
      priorityLocal: VulnTaskPriorityLocal;
      owner: string | null;
      dueDate: string | null;
      reviewDate: string | null;
      notesMd: string;
      decision: string | null;
      decisionNotes: string | null;
      evidence: string | null;
    }>
  ) {
    return this.tasks.patch(id, body);
  }

  @Post(":id/cves")
  async addCves(@Param("id") id: string, @Body() body: { cveIds?: string[] }) {
    return this.tasks.addCves(id, Array.isArray(body?.cveIds) ? body.cveIds : []);
  }

  @Post(":id/cves/:cveId/remove")
  async removeCve(@Param("id") id: string, @Param("cveId") cveId: string) {
    return this.tasks.removeCve(id, cveId);
  }

  @Get("by-cve/:cveId")
  async byCve(@Param("cveId") cveId: string) {
    return this.tasks.tasksByCve(cveId);
  }
}

