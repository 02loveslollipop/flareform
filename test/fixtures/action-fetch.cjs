let oidc = 0;
global.fetch = async (url) => {
  const target = String(url);
  if (target.startsWith("https://pipelines.actions.githubusercontent.com/"))
    return Response.json({
      value: `eyJhbGciOiJub25lIn0.fixture-${++oidc}.signature`,
    });
  if (target === "https://dns.02labs.me/v1/plan")
    return Response.json({
      plan_id: "11111111-1111-4111-8111-111111111111",
      changes: {
        "example.com": [
          {
            action: "create",
            type: "A",
            name: "example-app.example.com",
            key: "main-me",
          },
        ],
        "example.net": [
          {
            action: "create",
            type: "A",
            name: "example-app.example.net",
            key: "main-uk",
          },
        ],
      },
    });
  if (target === "https://dns.02labs.me/v1/apply")
    return Response.json({
      operation_id: "ffop_fixture",
      status: "complete",
      zones: {
        "example.com": { status: "success" },
        "example.net": { status: "success" },
      },
    });
  throw new Error("unexpected target");
};
