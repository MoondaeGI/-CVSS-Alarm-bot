import "dotenv/config";
import { Client, GatewayIntentBits, EmbedBuilder } from "discord.js";
import fetch from "node-fetch";
import { XMLParser } from "fast-xml-parser";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import OpenAI from "openai";
import {
  buildNvdQuerySpecFromQuestion,
  buildNvdQueryStringFromSpec,
} from "./query-builder.js";

// ───────────────────────────────────
// 환경변수
// ───────────────────────────────────
const { DISCORD_TOKEN, DISCORD_CHANNEL_ID, OPENAI_API_KEY } = process.env;

if (!DISCORD_TOKEN || !DISCORD_CHANNEL_ID || !OPENAI_API_KEY) {
  console.error("DISCORD_TOKEN / DISCORD_CHANNEL_ID / OPENAI_API_KEY 필요");
  process.exit(1);
}

// ───────────────────────────────────
// 상수
// ───────────────────────────────────

// NVD RSS (최신 CVE 목록)
const CVE_FEED_URL = "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml";

// 주기 (분)
const INTERVAL_MINUTES = 5;

// ───────────────────────────────────
// OpenAI 클라이언트
// ───────────────────────────────────
const openai = new OpenAI({
  apiKey: OPENAI_API_KEY,
});

// ───────────────────────────────────
// sqlite 초기화
// ───────────────────────────────────
let db;

async function initDb() {
  db = await open({
    filename: "./cve_state.db",
    driver: sqlite3.Database,
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS last_cve (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      cve_id TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);
}

async function getLastCveId() {
  const row = await db.get("SELECT cve_id FROM last_cve WHERE id = 1");
  return row ? row.cve_id : null;
}

async function setLastCveId(cveId) {
  const now = new Date().toISOString();
  await db.run(
    `
    INSERT INTO last_cve (id, cve_id, updated_at)
    VALUES (1, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      cve_id = excluded.cve_id,
      updated_at = excluded.updated_at;
    `,
    [cveId, now]
  );
}

// ───────────────────────────────────
// RSS에서 최신 CVE 1개만 가져오기
// ───────────────────────────────────
async function fetchLatestCve() {
  const res = await fetch(CVE_FEED_URL);
  if (!res.ok) {
    throw new Error(`CVE 피드 요청 실패: ${res.status}`);
  }

  const xml = await res.text();
  const parser = new XMLParser();
  const parsed = parser.parse(xml);

  const items = parsed?.rss?.channel?.item || [];
  if (!items.length) return null;

  const item = items[0]; // 가장 최신 1개
  return {
    id: item.link, // RSS link를 유일 ID로 사용
    title: item.title,
    link: item.link,
    pubDate: item.pubDate,
    description: item.description,
  };
}

// ───────────────────────────────────
// NVD API에서 CVSS 정보 가져오기
// ───────────────────────────────────
async function fetchCvssInfo(cveId) {
  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(
      cveId
    )}`;

    const res = await fetch(url);
    if (!res.ok) {
      console.error("NVD CVSS API 요청 실패:", res.status);
      return null;
    }

    const data = await res.json();
    const vuln = data.vulnerabilities?.[0];
    const metrics = vuln?.cve?.metrics;
    if (!metrics) return null;

    // v3.1 > v3.0 > v2 순으로 우선
    const v31 = metrics.cvssMetricV31?.[0];
    const v30 = metrics.cvssMetricV30?.[0];
    const v2 = metrics.cvssMetricV2?.[0];

    const source = v31 || v30 || v2;
    if (!source) return null;

    const cvssData = source.cvssData || source;

    const score = cvssData.baseScore;
    const severity = (
      cvssData.baseSeverity ||
      source.baseSeverity ||
      ""
    ).toUpperCase();
    const vector = cvssData.vectorString;
    const version = cvssData.version || (v2 ? "2.0" : "3.x");

    return {
      score,
      severity,
      vector,
      version,
    };
  } catch (e) {
    console.error("CVSS 정보 조회 오류:", e);
    return null;
  }
}

// ───────────────────────────────────
// NVD CVE 검색 (raw query 그대로 붙이기)
// ───────────────────────────────────
async function searchCveByRawQuery(rawQuery) {
  const base = "https://services.nvd.nist.gov/rest/json/cves/2.0";
  const url = `${base}?${rawQuery}`;

  console.log("검색 URL:", url);

  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`NVD 검색 요청 실패: ${res.status}`);
  }

  const data = await res.json();
  const vulns = data.vulnerabilities || [];
  return vulns;
}

// ───────────────────────────────────
// 심각도 → 색상 매핑
// ───────────────────────────────────
function severityToColor(severity) {
  if (!severity) return 0x808080;

  switch (severity.toUpperCase()) {
    case "CRITICAL":
      return 0x8b0000; // 진한 빨강
    case "HIGH":
      return 0xff0000; // 빨강
    case "MEDIUM":
      return 0xffa500; // 주황
    case "LOW":
      return 0x00b050; // 초록
    default:
      return 0x808080; // UNKNOWN
  }
}

// CVSS 문자열/벡터 포맷터
function formatCvss(cvss) {
  const scoreStr = cvss?.score
    ? `${cvss.score} (${cvss.severity || "UNKNOWN"}, v${cvss.version || "?"})`
    : "정보 없음";
  const vectorStr = cvss?.vector ? `\`${cvss.vector}\`` : "벡터 없음";

  return { scoreStr, vectorStr };
}

// 공통 Embed 생성기
function buildCveEmbed({
  titlePrefix,
  cveId,
  link,
  cvss,
  published,
  koreanData,
  summary,
}) {
  const { scoreStr, vectorStr } = formatCvss(cvss);
  const summaryText = (summary || "요약 없음").slice(0, 1000);

  return new EmbedBuilder()
    .setTitle(`${titlePrefix} ${cveId}`)
    .setURL(link)
    .setColor(severityToColor(cvss?.severity))
    .setTimestamp(new Date())
    .addFields(
      {
        name: "요약 (KR)",
        value: summaryText,
      },
      {
        name: "핵심 정보",
        value: [
          `• 제목(KR): ${koreanData.title_kr || "정보 없음"}`,
          `• 발행일: ${published || "-"}`,
        ].join("\n"),
      },
      {
        name: "CVSS",
        value: `${scoreStr}\n${vectorStr}`,
        inline: true,
      },
      {
        name: "URL",
        value: link,
      }
    )
    .setFooter({ text: "NVD CVE 알림봇" });
}

// ───────────────────────────────────
// OpenAI로 한국어 번역 + 요약 생성
// ───────────────────────────────────
async function summarizeCve(latest) {
  const cveId = latest.title.split(" ")[0];

  const englishJson = {
    id: cveId,
    title: latest.title,
    published: latest.pubDate ?? "",
    description: (latest.description ?? "").replace(/\s+/g, " "),
    url: latest.link,
  };

  const prompt = `
다음 CVE 정보를 기반으로 한국어 JSON과 요약을 생성하세요.

### 원본 정보(영문 JSON)
${JSON.stringify(englishJson, null, 2)}

### 출력 형식(JSON만 출력)
{
  "title_kr": "...",
  "desc_kr": "...",
  "summary": "..."
}

규칙:
- title_kr: title의 자연스러운 한국어 번역
- desc_kr: description의 한국어 번역 (없으면 ""로)
- summary:
  - 한국어로 2~3줄
  - 어떤 취약점인지, 어떤 컴포넌트/제품에 영향을 주는지
  - 위험도(낮음/중간/높음 추정)를 문장 안에 포함
`;

  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-4.1-mini",
      messages: [
        {
          role: "system",
          content: "You are a helpful cybersecurity assistant.",
        },
        { role: "user", content: prompt },
      ],
      temperature: 0.3,
    });

    const content = completion.choices[0]?.message?.content?.trim();
    if (!content) {
      throw new Error("빈 응답");
    }

    // LLM이 JSON만 출력하도록 요청했으므로 바로 파싱 시도
    return JSON.parse(content);
  } catch (e) {
    console.error("요약/번역 생성 오류:", e);
    return {
      title_kr: "번역 오류",
      desc_kr: "번역 오류",
      summary: "요약 생성 실패",
    };
  }
}

// ───────────────────────────────────
// 최신 CVE 변경 시에만 디스코드로 push
// ───────────────────────────────────
async function checkAndPush(client) {
  const channel = await client.channels.fetch(DISCORD_CHANNEL_ID);
  if (!channel) {
    console.error("채널을 찾을 수 없습니다.");
    return;
  }

  // 1) 최신 RSS 가져오기
  const latest = await fetchLatestCve();
  if (!latest) {
    console.log("RSS에 CVE 항목이 없습니다.");
    return;
  }

  const cveId = latest.title.split(" ")[0];
  const lastIdInDb = await getLastCveId();

  // 2) 이미 본 최신이면 skip
  if (lastIdInDb && lastIdInDb === latest.id) {
    console.log("변경된 최신 CVE 없음 → 스킵");
    return;
  }

  console.log(`새 최신 CVE 감지: ${latest.title}`);

  // 3) CVSS 정보 조회
  const cvss = await fetchCvssInfo(cveId);

  // 4) AI 번역/요약
  const ai = await summarizeCve(latest);

  const koreanData = {
    id: cveId,
    title_kr: ai.title_kr,
    published: latest.pubDate,
    description_kr: ai.desc_kr,
    url: latest.link,
  };

  // 6) Embed 생성 (공통 포맷)
  const embed = buildCveEmbed({
    titlePrefix: "🧨 새 최신 CVE:",
    cveId,
    link: latest.link,
    cvss,
    published: latest.pubDate,
    koreanData,
    summary: ai.summary,
  });

  // 7) 디스코드로 전송
  await channel.send({ embeds: [embed] });

  // 8) DB 업데이트
  await setLastCveId(latest.id);
}

// ───────────────────────────────────
// 디스코드 클라이언트 & 루프
// ───────────────────────────────────
const client = new Client({
  intents: [GatewayIntentBits.Guilds],
});

client.once("ready", async () => {
  console.log(`로그인 완료: ${client.user.tag}`);

  await initDb();

  // 처음 실행 시: 현재 최신 CVE는 DB에만 기록 (푸시 X)
  try {
    const latest = await fetchLatestCve();
    if (latest) {
      const lastId = await getLastCveId();
      if (!lastId) {
        console.log("초기 실행: 현재 최신 CVE를 DB에만 기록 (푸시 안 함)");
        await setLastCveId(latest.id);
      }
    }
  } catch (e) {
    console.error("초기 최신 CVE 기록 중 오류:", e);
  }

  // 주기적 체크
  setInterval(() => {
    checkAndPush(client).catch((e) =>
      console.error("주기적 CVE 체크 오류:", e)
    );
  }, INTERVAL_MINUTES * 60 * 1000);

  console.log(`주기적 CVE 체크 시작 (${INTERVAL_MINUTES}분 간격)`);
});

// ───────────────────────────────────
// 슬래시 커맨드 핸들러 (/cve-search)
// ───────────────────────────────────
client.on("interactionCreate", async (interaction) => {
  if (!interaction.isChatInputCommand()) return;
  if (interaction.commandName !== "cve-search") return;

  await interaction.deferReply(); // "생각 중..." 표시

  try {
    const question = interaction.options.getString("question");
    const spec = await buildNvdQuerySpecFromQuestion(question);
    const rawQuery = buildNvdQueryStringFromSpec(spec);
    
    const vulns = await searchCveByRawQuery(rawQuery);

    if (!vulns.length) {
      await interaction.editReply("검색 결과가 없습니다.");
      return;
    }

    // 일단 가장 첫번째 결과만 사용 (간단 버전)
    const cveObj = vulns[0].cve;
    const cveId = cveObj.id;

    const descEn =
      cveObj.descriptions?.find((d) => d.lang === "en")?.value ||
      cveObj.descriptions?.[0]?.value ||
      "";

    const published =
      cveObj.published || cveObj.publishedDate || cveObj.lastModified || "";

    const titleBase =
      cveObj.titles?.find((t) => t.lang === "en")?.title ||
      cveObj.titles?.[0]?.title ||
      "";

    // 우리가 쓰던 latest 형태로 변환
    const latestShape = {
      id: cveId,
      title: `${cveId} ${titleBase}`.trim(),
      link: `https://nvd.nist.gov/vuln/detail/${cveId}`,
      pubDate: published,
      description: descEn,
    };

    // CVSS 정보
    const cvss = await fetchCvssInfo(cveId);

    // AI 번역 + 요약
    const ai = await summarizeCve(latestShape);

    const koreanData = {
      id: cveId,
      title_kr: ai.title_kr,
      published: latestShape.pubDate,
      description_kr: ai.desc_kr,
      url: latestShape.link,
    };

    const embed = buildCveEmbed({
      titlePrefix: "🔎 CVE 검색 결과:",
      cveId,
      link: latestShape.link,
      cvss,
      published: latestShape.pubDate,
      koreanData,
      summary: ai.summary,
    });

    await interaction.editReply({ embeds: [embed] });
  } catch (e) {
    console.error("cve-search 처리 중 오류:", e);
    await interaction.editReply("검색 처리 중 오류가 발생했습니다.");
  }
});

// 로그인
client.login(DISCORD_TOKEN);
