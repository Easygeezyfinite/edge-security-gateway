import type { Env } from "./config.ts";
import { handleRequest } from "./gateway.ts";

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return handleRequest(request, env);
  },
};
