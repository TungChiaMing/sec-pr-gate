// 修好的版本：三個問題都處理掉，gate 會轉綠
import { NextResponse } from "next/server";
import { execFile } from "child_process";

const ALLOWED_HOST = /^[a-zA-Z0-9.-]+$/;

export async function POST(req: Request) {
  const { expr, host } = await req.json();

  // 不用 eval：只接受數字
  const value = Number(expr);
  if (!Number.isFinite(value)) {
    return NextResponse.json({ error: "expr must be a number" }, { status: 400 });
  }

  // execFile + 參數陣列：沒有 shell，字串串接無法注入；再加 allowlist
  if (typeof host !== "string" || !ALLOWED_HOST.test(host)) {
    return NextResponse.json({ error: "invalid host" }, { status: 400 });
  }
  const out = await new Promise<string>((resolve) =>
    execFile("ping", ["-c", "1", host], (_e, stdout) => resolve(stdout))
  );

  // secret 從環境變數來，不寫死在原始碼
  return NextResponse.json({ value, out, key: (process.env.STRIPE_KEY ?? "").slice(0, 8) });
}
