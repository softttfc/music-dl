#!/usr/bin/env node
/**
 * runtime_hook.js
 * 在 Node 里模拟 LX Music 环境，跑一遍混淆 JS，
 * 收集所有运行时字符串、请求 URL、返回结果。
 *
 * 用法: node runtime_hook.js input/obf.js output/runtime-dump.json
 */

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const srcPath = process.argv[2];
const outPath = process.argv[3] || "runtime-dump.json";

if (!srcPath) {
  console.error("用法: node runtime_hook.js 原文件.js [输出.json]");
  process.exit(1);
}

const source = fs.readFileSync(srcPath, "utf-8");

// ============================================================
// 1. 收集容器
// ============================================================
const dump = {
  strings: new Set(),
  logs: [],
  requests: [],
  responses: [],
  sends: [],
  events: [],
  errors: [],
  handlers: {},
};

function recordString(s) {
  if (typeof s === "string" && s.length > 0 && s.length < 2000) {
    dump.strings.add(s);
  }
  return s;
}

function walkObject(obj, fn, seen = new WeakSet()) {
  if (obj === null || typeof obj !== "object") {
    if (typeof obj === "string") fn(obj);
    return;
  }
  if (seen.has(obj)) return;
  seen.add(obj);
  for (const key of Object.keys(obj)) {
    fn(key);
    walkObject(obj[key], fn, seen);
  }
}

// ============================================================
// 2. 模拟 LX 环境
// ============================================================
const EVENT_NAMES = {
  request: "request",
  inited: "inited",
  updateAlert: "updateAlert",
};

const lx = {
  EVENT_NAMES,
  version: "2.0.0",

  request: (url, options, callback) => {
    recordString(url);
    dump.requests.push({
      url,
      method: options?.method || "GET",
      headers: options?.headers || {},
      body: options?.body || null,
      time: new Date().toISOString(),
    });

    // 模拟返回，让代码继续走
    const fakeBody = JSON.stringify({
      code: 200,
      msg: "ok",
      data: {
        url: "https://example.com/fake.mp3",
        quality: "320k",
        musicUrl: "https://example.com/fake.mp3",
      },
    });

    const resp = {
      statusCode: 200,
      headers: { "content-type": "application/json" },
      body: fakeBody,
    };
    dump.responses.push({ url, body: fakeBody });

    if (typeof callback === "function") {
      setTimeout(() => callback(null, resp), 0);
    }
    return Promise.resolve(resp);
  },

  on: (event, handler) => {
    recordString(event);
    dump.events.push(event);
    if (!dump.handlers[event]) dump.handlers[event] = [];
    dump.handlers[event].push(handler);
  },

  send: (event, data) => {
    recordString(event);
    dump.sends.push({ event, data });
    if (typeof data === "object" && data !== null) {
      walkObject(data, recordString);
    }
  },
};

// ============================================================
// 3. 构造沙箱
// ============================================================
const sandbox = {
  globalThis: null,
  console: {
    log: (...args) => {
      dump.logs.push(args.map(String).join(" "));
      args.forEach(recordString);
    },
    error: (...args) => {
      dump.logs.push("[error] " + args.map(String).join(" "));
      args.forEach(recordString);
    },
    warn: (...args) => {
      dump.logs.push("[warn] " + args.map(String).join(" "));
      args.forEach(recordString);
    },
  },
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
  Promise,
  JSON,
  Math,
  Date,
  String,
  Number,
  Boolean,
  Array,
  Object,
  RegExp,
  Error,
  TypeError,
  parseInt,
  parseFloat,
  isNaN,
  encodeURIComponent,
  decodeURIComponent: (s) => {
    recordString(s);
    return decodeURIComponent(s);
  },
  encodeURI,
  decodeURI,
  unescape,
  escape,
  atob: (s) => {
    recordString(s);
    return Buffer.from(s, "base64").toString("binary");
  },
  btoa: (s) => {
    recordString(s);
    return Buffer.from(s, "binary").toString("base64");
  },
  TextEncoder,
  TextDecoder,
  URL,
  URLSearchParams,
  fetch: (...args) => {
    recordString(String(args[0]));
    dump.requests.push({ url: String(args[0]), via: "fetch" });
    return Promise.resolve({
      ok: true,
      status: 200,
      text: () => Promise.resolve("{}"),
      json: () => Promise.resolve({}),
    });
  },
};
sandbox.globalThis = sandbox;
sandbox.window = sandbox;
sandbox.self = sandbox;
sandbox.lx = lx;

// ============================================================
// 4. 执行原 JS
// ============================================================
const context = vm.createContext(sandbox);

try {
  vm.runInContext(source, context, {
    filename: srcPath,
    timeout: 15000,
  });
  console.error("[+] 原 JS 执行成功");
} catch (e) {
  dump.errors.push({ message: e.message, stack: e.stack });
  console.error("[!] 执行出错:", e.message);
}

// ============================================================
// 5. 主动触发事件
// ============================================================
async function triggerHandlers() {
  const platforms = ["kg", "tx", "wy", "kw", "mg"];
  const actions = ["musicUrl"];

  for (const event of Object.keys(dump.handlers)) {
    for (const handler of dump.handlers[event]) {
      for (const action of actions) {
        for (const source of platforms) {
          const payload = {
            action,
            source,
            info: {
              musicInfo: {
                id: "test123",
                songmid: "test123",
                hash: "test123",
                name: "测试歌曲",
                singer: "测试歌手",
                album: "测试专辑",
                quality: "320k",
              },
              type: "320k",
            },
          };
          try {
            const result = await handler(payload);
            if (result) {
              dump.sends.push({ triggered: true, event, payload, result });
              walkObject(result, recordString);
            }
          } catch (e) {
            dump.errors.push({
              triggered: true,
              event,
              payload,
              message: e.message,
            });
          }
        }
      }
    }
  }
}

triggerHandlers().then(() => {
  // ============================================================
  // 6. 输出
  // ============================================================
  const output = {
    summary: {
      stringCount: dump.strings.size,
      requestCount: dump.requests.length,
      sendCount: dump.sends.length,
      eventCount: dump.events.length,
      errorCount: dump.errors.length,
    },
    strings: Array.from(dump.strings).sort(),
    requests: dump.requests,
    responses: dump.responses,
    sends: dump.sends,
    events: dump.events,
    logs: dump.logs,
    errors: dump.errors,
  };

  fs.mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(output, null, 2), "utf-8");

  console.error(`[+] 输出: ${outPath}`);
  console.error(`    字符串: ${output.summary.stringCount}`);
  console.error(`    请求:   ${output.summary.requestCount}`);
  console.error(`    发送:   ${output.summary.sendCount}`);
  console.error(`    错误:   ${output.summary.errorCount}`);
});
