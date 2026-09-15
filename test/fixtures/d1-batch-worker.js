// Test-only Worker, never used by the production Wrangler configuration.
export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    if (path === "/setup") {
      await env.DB.prepare(
        "CREATE TABLE IF NOT EXISTS batch_probe(id INTEGER PRIMARY KEY)",
      ).run();
      return new Response("ready");
    }
    if (path === "/conflict") {
      try {
        await env.DB.batch([
          env.DB.prepare("INSERT INTO batch_probe(id) VALUES (?)").bind(1),
          env.DB.prepare("INSERT INTO batch_probe(id) VALUES (?)").bind(1),
        ]);
        return new Response("unexpected success", { status: 500 });
      } catch {
        return new Response("rolled back");
      }
    }
    if (path === "/count") {
      const row = await env.DB.prepare(
        "SELECT count(*) AS n FROM batch_probe",
      ).first();
      return new Response(String(row.n));
    }
    return new Response("not found", { status: 404 });
  },
};
