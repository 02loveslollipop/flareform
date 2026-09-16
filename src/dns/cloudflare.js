import { FlareFormError } from "../errors.js";
import { parseStrictJson } from "../strict-json.js";
import { parseManifestObject } from "./manifest.js";

const API_BASE = "https://api.cloudflare.com/client/v4";
const ID = /^[0-9a-f]{32}$/;
const MAX_RESPONSE_BYTES = 262144;
const MAX_PAGES = 100;
const PER_PAGE = 100;
function fail() {
  throw new FlareFormError("CLOUDFLARE_API_ERROR");
}
function bounded(promise, signal) {
  if (signal.aborted) fail();
  return new Promise((resolve, reject) => {
    const timeout = () => reject(new FlareFormError("CLOUDFLARE_API_ERROR"));
    signal.addEventListener("abort", timeout, { once: true });
    Promise.resolve(promise)
      .then(resolve, reject)
      .finally(() => signal.removeEventListener("abort", timeout));
  });
}
function zoneId(zone) {
  if (
    !zone ||
    typeof zone !== "object" ||
    !ID.test(zone.cloudflare_zone_id ?? "") ||
    (zone.enabled !== true && zone.enabled !== 1)
  )
    fail();
  return zone.cloudflare_zone_id;
}
function recordId(id) {
  if (typeof id !== "string" || !ID.test(id)) fail();
  return id;
}
function bodyRecord(record, zone) {
  if (
    !record ||
    typeof record !== "object" ||
    !["A", "AAAA", "CNAME", "SRV", "TXT"].includes(record.type) ||
    typeof record.name !== "string" ||
    !/^[a-z0-9_.-]{1,253}$/.test(record.name) ||
    !Number.isSafeInteger(record.ttl) ||
    record.ttl < 1 ||
    record.ttl > 86400
  )
    fail();
  const tags = record.tags;
  if (
    !Array.isArray(tags) ||
    tags.length !== 3 ||
    tags.some(
      (tag) => typeof tag !== "string" || !/^[a-z0-9-]+:[a-z0-9-]+$/.test(tag),
    )
  )
    fail();
  const base = {
    type: record.type,
    name: record.name,
    ttl: record.ttl,
    tags,
    comment: record.comment,
  };
  if (
    typeof record.comment !== "string" ||
    !/^Managed by FlareForm for GitHub repository [1-9][0-9]*$/.test(
      record.comment,
    )
  )
    fail();
  if (record.type === "SRV") {
    if (
      typeof record.data !== "object" ||
      !record.data ||
      Object.keys(record.data).sort().join() !== "port,priority,target,weight"
    )
      fail();
    try {
      parseManifestObject(
        {
          version: 1,
          reconciliation: "keep",
          records: [
            {
              key: "validated",
              zone: zone.name,
              name: record.name,
              type: "SRV",
              ttl: record.ttl,
              ...record.data,
            },
          ],
        },
        [zone],
      );
    } catch {
      fail();
    }
    return { ...base, data: record.data };
  }
  if (typeof record.content !== "string" || record.content.length > 1024)
    fail();
  try {
    parseManifestObject(
      {
        version: 1,
        reconciliation: "keep",
        records: [
          {
            key: "validated",
            zone: zone.name,
            name: record.name,
            type: record.type,
            ttl: record.ttl,
            content: record.content,
            ...(record.proxied === undefined
              ? {}
              : { proxied: record.proxied }),
          },
        ],
      },
      [zone],
      { allowTxt: true },
    );
  } catch {
    fail();
  }
  return {
    ...base,
    content: record.content,
    ...(["A", "AAAA", "CNAME"].includes(record.type)
      ? { proxied: record.proxied === true }
      : {}),
  };
}
function validateRecord(record) {
  if (
    !record ||
    typeof record !== "object" ||
    !ID.test(record.id ?? "") ||
    typeof record.name !== "string" ||
    typeof record.type !== "string" ||
    !Number.isSafeInteger(record.ttl) ||
    !Array.isArray(record.tags ?? []) ||
    (typeof record.comment !== "string" && record.comment !== undefined)
  )
    fail();
  return record;
}
function verifyMutationResponse(record, payload) {
  validateRecord(record);
  if (
    record.name !== payload.name ||
    record.type !== payload.type ||
    record.comment !== payload.comment ||
    !Array.isArray(record.tags) ||
    record.tags.length !== payload.tags.length ||
    payload.tags.some((tag) => !record.tags.includes(tag))
  )
    fail();
  if (
    payload.type === "SRV"
      ? !record.data ||
        ["priority", "weight", "port", "target"].some(
          (key) => record.data[key] !== payload.data[key],
        )
      : record.content !== payload.content
  )
    fail();
  return record;
}

/** Fixed-origin Cloudflare DNS client. No caller-provided URL or path segments. */
export function createCloudflareClient({
  token,
  fetchImpl = fetch,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  timeoutMs = 4000,
}) {
  if (typeof token !== "string" || token.length < 1 || /[\r\n]/.test(token))
    fail();
  async function request(method, path, payload, retryRead = false) {
    const url = `${API_BASE}${path}`;
    for (let attempt = 0; attempt < (retryRead ? 3 : 1); attempt++) {
      const signal = AbortSignal.timeout(timeoutMs);
      try {
        const response = await bounded(
          fetchImpl(url, {
            method,
            // Workerd supports manual redirect handling, not the Fetch API's
            // "error" mode. Redirect responses are rejected below before a
            // body is read or a second request can carry the bearer token.
            redirect: "manual",
            signal,
            headers: {
              authorization: `Bearer ${token}`,
              accept: "application/json",
              ...(payload === undefined
                ? {}
                : { "content-type": "application/json" }),
            },
            ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
          }),
          signal,
        );
        if (
          response.redirected ||
          (response.url && response.url !== url) ||
          (response.status >= 300 && response.status < 400)
        )
          fail();
        if (!response.ok) {
          if (
            retryRead &&
            attempt < 2 &&
            (response.status === 429 || response.status >= 500)
          ) {
            await sleep(100 * (attempt + 1));
            continue;
          }
          fail();
        }
        const length = response.headers.get("content-length");
        if (length && Number(length) > MAX_RESPONSE_BYTES) fail();
        const reader = response.body?.getReader();
        if (!reader) fail();
        const chunks = [];
        let size = 0;
        try {
          while (true) {
            const { done, value } = await bounded(reader.read(), signal);
            if (done) break;
            size += value.byteLength;
            if (size > MAX_RESPONSE_BYTES) fail();
            chunks.push(value);
          }
        } finally {
          if (signal.aborted) await reader.cancel().catch(() => {});
          reader.releaseLock();
        }
        const bytes = new Uint8Array(size);
        let offset = 0;
        for (const chunk of chunks) {
          bytes.set(chunk, offset);
          offset += chunk.length;
        }
        const envelope = parseStrictJson(
          new TextDecoder("utf-8", { fatal: true }).decode(bytes),
          { maxBytes: MAX_RESPONSE_BYTES, maxDepth: 24, maxNodes: 12000 },
        );
        if (
          !envelope ||
          typeof envelope !== "object" ||
          envelope.success !== true ||
          (Array.isArray(envelope.errors) && envelope.errors.length > 0) ||
          !Object.hasOwn(envelope, "result")
        )
          fail();
        return envelope;
      } catch (error) {
        if (error instanceof FlareFormError) throw error;
        if (retryRead && attempt < 2 && !signal.aborted) {
          await sleep(100 * (attempt + 1));
          continue;
        }
        fail();
      }
    }
    fail();
  }
  return {
    async listRecords(zone) {
      const id = zoneId(zone);
      const all = [];
      const seen = new Set();
      let expectedPages = null;
      let expectedTotal = null;
      for (let page = 1; page <= MAX_PAGES; page++) {
        const response = await request(
          "GET",
          `/zones/${id}/dns_records?page=${page}&per_page=${PER_PAGE}`,
          undefined,
          true,
        );
        if (
          !Array.isArray(response.result) ||
          !response.result_info ||
          response.result_info.page !== page ||
          !Number.isSafeInteger(response.result_info.total_pages) ||
          response.result_info.total_pages < 0 ||
          response.result_info.total_pages > MAX_PAGES
        )
          fail();
        if (response.result_info.total_pages === 0) {
          if (
            page !== 1 ||
            response.result.length !== 0 ||
            response.result_info.total_count !== 0
          )
            fail();
          return [];
        }
        if (
          expectedPages !== null &&
          response.result_info.total_pages !== expectedPages
        )
          fail();
        expectedPages = response.result_info.total_pages;
        if (response.result_info.total_count !== undefined) {
          if (
            !Number.isSafeInteger(response.result_info.total_count) ||
            response.result_info.total_count < 0 ||
            (expectedTotal !== null &&
              response.result_info.total_count !== expectedTotal)
          )
            fail();
          expectedTotal = response.result_info.total_count;
        }
        if (page < expectedPages && response.result.length === 0) fail();
        for (const record of response.result) {
          validateRecord(record);
          if (seen.has(record.id)) fail();
          seen.add(record.id);
          all.push(record);
        }
        if (page === response.result_info.total_pages) {
          if (expectedTotal !== null && all.length !== expectedTotal) fail();
          return all;
        }
      }
      fail();
    },
    async create(zone, record) {
      const payload = bodyRecord(record, zone);
      const result = await request(
        "POST",
        `/zones/${zoneId(zone)}/dns_records`,
        payload,
      );
      return verifyMutationResponse(result.result, payload);
    },
    async patch(zone, id, record) {
      const payload = bodyRecord(record, zone);
      const result = await request(
        "PATCH",
        `/zones/${zoneId(zone)}/dns_records/${recordId(id)}`,
        payload,
      );
      if (result.result?.id !== id) fail();
      return verifyMutationResponse(result.result, payload);
    },
    async delete(zone, id) {
      const result = await request(
        "DELETE",
        `/zones/${zoneId(zone)}/dns_records/${recordId(id)}`,
      );
      if (!result.result || result.result.id !== id) fail();
      return result.result;
    },
    async batch(zone, operations) {
      const id = zoneId(zone);
      if (
        !operations ||
        typeof operations !== "object" ||
        Object.keys(operations).some(
          (key) => !["deletes", "patches", "posts"].includes(key),
        )
      )
        fail();
      if (
        ["deletes", "patches", "posts"].some(
          (key) =>
            !Array.isArray(operations[key] ?? []) ||
            (operations[key] ?? []).length > 100,
        )
      )
        fail();
      const payload = {
        deletes: (operations.deletes ?? []).map((id) => ({ id: recordId(id) })),
        patches: (operations.patches ?? []).map(({ id, record }) => ({
          id: recordId(id),
          ...bodyRecord(record, zone),
        })),
        posts: (operations.posts ?? []).map((record) =>
          bodyRecord(record, zone),
        ),
      };
      const result = await request(
        "POST",
        `/zones/${id}/dns_records/batch`,
        payload,
      );
      if (
        !result.result ||
        typeof result.result !== "object" ||
        ["deletes", "patches", "posts"].some(
          (key) =>
            !Array.isArray(result.result[key]) ||
            result.result[key].length !== payload[key].length,
        )
      )
        fail();
      for (let index = 0; index < payload.deletes.length; index++)
        if (result.result.deletes[index]?.id !== payload.deletes[index].id)
          fail();
      for (let index = 0; index < payload.patches.length; index++) {
        if (result.result.patches[index]?.id !== payload.patches[index].id)
          fail();
        verifyMutationResponse(
          result.result.patches[index],
          payload.patches[index],
        );
      }
      for (let index = 0; index < payload.posts.length; index++)
        verifyMutationResponse(
          result.result.posts[index],
          payload.posts[index],
        );
      return result.result;
    },
  };
}
