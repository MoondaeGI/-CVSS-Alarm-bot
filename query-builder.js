import OpenAI from "openai";
import http from "http";

// Render healthcheck용
const PORT = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("OK");
});

server.listen(PORT, () => {
  console.log(`Render healthcheck server listening on port ${PORT}`);
});

// ───────────────────────────────────
// OpenAI 초기화
// ───────────────────────────────────
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// ───────────────────────────────────
// 자연어 질문 → NVD 검색 스펙(JSON)
// ───────────────────────────────────
export async function buildNvdQuerySpecFromQuestion(question) {
  const prompt = `
당신은 NVD CVE 검색 API 쿼리를 생성하는 보안 전문가입니다.
사용자의 자연어 질문을 기반으로 아래 JSON 형식으로만 출력하세요.

출력 JSON 형식:
{
  "keyword": "검색 키워드 (없으면 null)",
  "cvssSeverity": "LOW | MEDIUM | HIGH | CRITICAL | null",
  "maxResults": 5,
  "publishedFrom": "YYYY-MM-DD 또는 null",
  "publishedTo": "YYYY-MM-DD 또는 null"
}

세부 규칙:
- keyword: 제품명, 기술명 또는 핵심 단어 1개만 사용
- cvssSeverity: 없으면 null
- maxResults: 항상 1~20 사이 숫자
- 기간:
  - "최근 1년" → publishedFrom을 1년 전 날짜로 설정
  - "최근 6개월", "올해", "2023년" 같이 대략적이면 YYYY-MM-DD로 적당히 변환
- JSON 외의 텍스트는 절대 출력하지 말 것

사용자 질문:
${question}
`.trim();

  const completion = await openai.chat.completions.create({
    model: "gpt-4.1-mini",
    messages: [
      {
        role: "system",
        content: "You only output valid JSON. No explanation.",
      },
      { role: "user", content: prompt },
    ],
    temperature: 0.2,
  });

  const content = completion.choices[0]?.message?.content?.trim();
  if (!content) {
    throw new Error("LLM이 빈 응답을 반환했습니다.");
  }

  try {
    const json = JSON.parse(content);
    json.rawQuestion = question; // fallback 용도로 포함 가능
    return json;
  } catch (err) {
    console.error("LLM JSON 파싱 오류:", content);
    throw err;
  }
}

// ───────────────────────────────────
// 검색 스펙(JSON) → 실제 NVD 쿼리스트링 생성
// ───────────────────────────────────
export function buildNvdQueryStringFromSpec(spec) {
  const params = new URLSearchParams();

  // keyword
  if (spec.keyword && spec.keyword !== "null") {
    params.set("keywordSearch", spec.keyword);
  }

  // CVSS severity
  if (spec.cvssSeverity && spec.cvssSeverity !== "null") {
    params.set("cvssV3Severity", spec.cvssSeverity.toUpperCase());
  }

  // 날짜 조건
  if (spec.publishedFrom && spec.publishedFrom !== "null") {
    params.set("pubStartDate", `${spec.publishedFrom}T00:00:00.000`);
  }

  if (spec.publishedTo && spec.publishedTo !== "null") {
    params.set("pubEndDate", `${spec.publishedTo}T23:59:59.000`);
  }

  // 결과 개수
  const max = spec.maxResults && spec.maxResults > 0 ? spec.maxResults : 5;
  params.set("resultsPerPage", String(Math.min(max, 20)));

  // fallback: LLM이 너무 비어있는 spec을 만들 경우
  if ([...params.keys()].length === 0 && spec.rawQuestion) {
    params.set("keywordSearch", spec.rawQuestion);
    params.set("resultsPerPage", "5");
  }

  return params.toString();
}
