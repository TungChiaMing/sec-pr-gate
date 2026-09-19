// app/api/run/route.ts — 故意含漏洞的 Next.js API route（demo 用，會被 gate 擋下）
import { NextResponse } from "next/server";
import { exec } from "child_process";

// TP: hardcoded secret（semgrep p/secrets + trivy secret scanner）
const STRIPE_KEY = "sk_live_REPLACE_WITH_A_FAKE_LOOKING_KEY";  // ← demo 時換成
// sk_live_ 後面接 24 個以上的英數字（不要底線），才會被 p/secrets 與 trivy 命中。
// 這裡刻意放不會命中的 placeholder，免得 sec-pr-gate 自己的 push 被 secret scanning 擋。

export async function POST(req: Request) {
  const { expr, host } = await req.json();

  // TP: eval() on user input -> RCE
  const value = eval(expr);

  // TP: command injection（字串串接進 child_process.exec）
  const out = await new Promise<string>((resolve) =>
    exec(`ping -c 1 ${host}`, (_e, stdout) => resolve(stdout))
  );

  return NextResponse.json({ value, out, key: STRIPE_KEY.slice(0, 8) });
}
